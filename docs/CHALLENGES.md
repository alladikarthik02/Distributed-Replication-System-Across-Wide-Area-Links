# `wanrep` — bug journal & engineering challenges

Every bug hit while building this system, written down with the *reasoning*, not just the
fix. Small ones are included on purpose — a planning mistake sits next to a
design-breaking discovery — because the point is that reading this cold should make each
failure legible, and defensible out loud.

**Format per entry:** Symptom → Hypotheses (including the wrong ones) → How I isolated it
→ Root cause → Fix → Generalizes to.

Wrong hypotheses are kept deliberately. Disproving your own first guess is the most
defensible story there is; a journal that only records correct conclusions hides the part
of the work that was actually hard.

**Legend:** 🧱 environment/tooling · 🐛 code defect · 🔬 design-invalidating discovery ·
⚔️ concurrency/timing · 💾 durability/crash-consistency · 🌐 network/protocol

---

## B1 🔬 Planned to reuse project #1's chunker; it existed but was not committed

**Symptom.** The plan for this project assumed three components could be carried over from
`dedupe` (project #1): `sha256.h`, `crc32c.h`, and the FastCDC chunker. A file listing
showed all three present. But the memory of the project's state said the chunker was
task T2, *not started*.

**Hypotheses.**
- (H1) My record of `dedupe`'s state was simply stale — T2 had been finished since. —
  *Partly right, and the tempting one.* It would have justified copying the file.
- (H2) The file is a scratch or abandoned draft. — Worth ruling out before depending on it.

**How I isolated it.** `git log --oneline` showed the last commit was `ac2096a T1: SHA-256
+ CRC32C`. `git status --short` showed `?? include/dedupe/chunker.h`, `?? tests/test_chunker.cpp`,
and `M CMakeLists.txt`. So the chunker was real, substantial (201 lines with a 363-line
test suite), and **untracked** — the working tree of a task that was still in flight in
another session. Confirmation arrived shortly after: `dedupe/README.md` changed on disk
mid-session to mark T2 done.

**Root cause.** Not a code defect — a planning defect. "Is the file there?" and "is there
a version of this I can depend on?" are different questions, and I had answered the first
while believing I had answered the second.

**Fix.** Carry over only what is committed: `sha256.h` and `crc32c.h` (and the test
harness). Write this project's chunker fresh in T1. `dedupe` is left untouched — editing a
repository with another session's uncommitted work in it is how you destroy someone's
afternoon.

**Generalizes to.** Reuse has a precondition: the thing reused must be a *named, committed
version*, not a path that currently happens to contain bytes. Depending on an untracked
file couples your build to somebody's editor buffer — it cannot be checked out, cannot be
rolled back, and will differ from itself tomorrow. `ls` tells you a file exists;
only `git status` tells you it exists *for anyone but you*.

---

## B2 🔬💾 `flock()` succeeds twice on the bind mount — S16 was silently unenforceable

**The single most valuable thing T0 produced.**

**Symptom.** None. That is the entire problem. `test_harness` asserted that a second
`flock(LOCK_EX | LOCK_NB)` on an independently-opened fd fails with `EWOULDBLOCK`, and it
passed, green, on the first run and 25 runs after that.

**What made me look anyway.** The test creates its temporary directory under `/tmp`. The
container has *two* filesystems: `/tmp` is container-local overlayfs, and `/work` is the
macOS project directory shared in over virtiofs. I had verified a property of one
filesystem and written a safety requirement (SPEC S16) that would be enforced on
whichever filesystem a user chose. Those are not the same claim, and `/work` is the more
natural place for someone to put a store — it is the directory they can see.

**Hypotheses.**
- (H1) The two filesystems behave the same for locking; gateway filesystems usually get
  `fsync` wrong, not `flock`. — **Wrong**, and it is the interesting kind of wrong: it
  named the right suspect (a gateway filesystem cutting corners) and then guessed the
  wrong primitive. `fsync` is the famous one, so it is where attention goes.
- (H2) `flock` on virtiofs fails outright with `ENOTSUP`. — Also wrong, and it would have
  been the *good* outcome: a loud error is a safe error.
- (H3) `flock` silently no-ops. — Correct, and the worst of the three.

**How I isolated it.** Wrote `scratch/spike_fs.cpp` — a 60-line probe running the same
four operations (`rename` over an existing file, `fsync(file)`, `fsync(dir)`,
`flock` × 2) against both mounts, printing `strerror(errno)` for each. Two independent
`open()` calls, not `dup()`: `flock` locks attach to the *open file description*, so a
dup'd descriptor shares the lock and would report success on any filesystem — testing
nothing. That distinction is what makes the probe work inside a single process.

```
=== overlayfs (/tmp)                === virtiofs (/work)
  rename over existing : ok           rename over existing : ok
  fsync(file)          : ok           fsync(file)          : ok
  fsync(dir)           : ok           fsync(dir)           : ok
  flock #1             : acquired     flock #1             : acquired
  flock #2 (must fail) : EWOULDBLOCK  flock #2 (must fail) : !!! ALSO ACQUIRED
```

Every durability primitive behaves identically on both. Only the lock differs — and it
differs by succeeding.

**Root cause.** Docker Desktop's virtiofs share does not implement `flock` exclusion. The
call returns 0 and does nothing. A target store placed on `/work` would have had two
processes appending into the same container file with no error, no warning, and no
diagnostic — corruption whose first symptom would be a CRC failure days later, in a
component nowhere near the actual fault.

**Fix.** Three parts, because a comment would not have helped — the failure is silent and
occurs on a filesystem a user would reasonably choose:

1. `include/wanrep/fsprobe.h` — `probe_flock_exclusion(dir)`, which ships in the product,
   not just the tests.
2. **The target store runs it at open time and refuses to open** where exclusion cannot
   be enforced. A silent corruption becomes a startup error that names its own cause.
3. Test and benchmark stores live on container-local storage. (Independently correct:
   a store on the bind mount would make every I/O benchmark a measurement of virtiofs
   rather than of this code.)

SPEC §2.5 now records both filesystems, S16's enforcement column includes the probe, and
§8.10 states the limitation instead of implying we tested something we did not.

**Generalizes to.** Three things, and the third is the one worth remembering:

- **A POSIX call returning 0 is not evidence that it did anything.** `flock` returned 0
  both times. Success is the absence of an error, which is not the presence of an effect.
- **A green test proves a property of the environment it ran in.** Ask what that
  environment was and whether production shares it. Here, one `mkdtemp` prefix was the
  entire difference between a verified invariant and an unenforced one.
- **When a safety mechanism depends on the environment, ship the check, not the
  assumption.** The probe is ~40 lines. The class of bug it prevents is the kind you
  debug for two days, in the wrong file.

---

## B3 🔬 A long run of one byte can *never* be cut — the Gear hash freezes after 64 bytes

**Symptom.** The T1 chunker test reported, for three different fill bytes:

```
note: fill=0x00 -> 16 chunks, 16 forced at max (100%)
note: fill=0xff -> 16 chunks, 16 forced at max (100%)
note: fill=0x41 -> 16 chunks, 16 forced at max (100%)
```

Every single chunk of a constant-byte run hit the hard 64 KiB ceiling. Nothing failed —
`min`/`max` were respected and the input tiled correctly — but "content-defined chunking
never once let the content define a boundary" is the kind of clean 100% that is either a
deep property or a bug, and 100% across three unrelated byte values ruled out
coincidence immediately.

**Hypotheses.**
- (H1) An off-by-one in the mask regions — the loop never reaches the loose-mask branch,
  so the easy-to-cut region is dead code. — *Rejected:* random data cuts constantly and
  its measured distribution straddles `avg` (p50 = 9 198 B, above the 8 192 B boundary),
  which is only reachable through the loose-mask branch.
- (H2) The Gear table has poor entropy for these byte values. — *Rejected:* the table
  test showed mean popcount 31.80/64 and all 256 entries distinct and non-zero. And it
  would not explain identical behaviour across three unrelated values.
- (H3) On constant input the hash stops depending on the data. — Correct, and much
  stronger than "stops depending": it stops *moving*.

**How I isolated it.** Unrolled the recurrence by hand instead of instrumenting.
On a constant run, `h_{k+1} = (h_k << 1) + G` with `G = gear[b]`, so

```
h_0 = 0,  h_1 = G,  h_2 = 3G,  h_3 = 7G,  ...   h_k = (2^k - 1) * G   (mod 2^64)
```

and for `k >= 64`, `2^k ≡ 0 (mod 2^64)`, giving **`h_k = -G` for every k from 64 onward**.
The hash does not become predictable — it becomes *constant*. So whether a constant run
ever cuts is decided by a single question per byte value ("does `-G` match the mask?"),
not by the data or its length.

`scratch/spike_gear_constant.cpp` checked that against all 256 byte values:

```
closed form h_k = -G for k>=64 : CONFIRMED for all 256 byte values
byte values whose steady hash matches mask_s (15 bits) : 0 / 256
byte values whose steady hash matches mask_l (11 bits) : 0 / 256
byte values that cut during the 63-byte warm-up        : 0 / 256
```

Zero out of 256. **No constant-byte run of any value can ever be cut by content.** The
expected count is small by construction — 256 × 2⁻¹¹ ≈ 0.125 for the loose mask — so
zero is the unremarkable outcome of arithmetic, not bad luck.

**Root cause.** Not a defect. It is an inherent property of a shift-based rolling hash:
the "window" exists only because old bytes shift off the top of the word, and when every
byte is identical the sum telescopes to a fixed point. Rabin fingerprinting, which
multiplies and reduces modulo an irreducible polynomial, does not have this fixed point.
It is the price of the one-shift-one-add hot loop that made Gear the right choice.

**Fix.** None to the chunker — but the *consequence* had to be understood before it could
be dismissed, and it turned out to be benign for exactly one reason: **all those forced
chunks are byte-identical.** A 1 GiB zero region becomes 16 384 chunks that share one
fingerprint and collapse to a single stored chunk. The cost is bookkeeping (16 384
manifest entries at 36 B ≈ 576 KiB), not payload. Recorded as:

1. `chunker_constant_runs_produce_identical_max_size_chunks` — asserts the forced-cut
   behaviour *and* that all such chunks are identical, so the benign-ness is a test, not
   a comment.
2. `gear_hash_freezes_on_a_constant_run_after_64_bytes` — asserts the closed form
   directly, so a future change to the table or the shift width breaks the *reasoning*
   loudly rather than leaving plausible-looking chunk sizes behind.
3. SPEC §8.9 now says the chunk-size distribution must be measured **per content class**,
   because "≈8 KiB average" is true for random data (measured mean 9 316 B) and false by
   8× for sparse data.

**Generalizes to.** A rolling hash's window is an emergent property of its arithmetic,
not a thing it owns — so it is worth asking what happens at the arithmetic's fixed
points. More usefully: when a measurement comes back at exactly 100% or exactly 0%, the
explanation is almost never statistical. Derive it. Three minutes of unrolling a
recurrence produced a complete answer where instrumenting the loop would have produced
another table of numbers to interpret.

**A note on the sibling result.** The boundary-preservation test reported exactly
**100.00%** for content-defined chunking against **0.20%** for the fixed-size control, and
those numbers deserved the same suspicion. They survive it: the Gear hash at modified
position `i` depends only on bytes `[i-64, i-1]`, which is the identical window sitting at
original position `i-1`, so 64 bytes past an insertion the two hash streams are the same
sequence offset by one, and every downstream cut lands at exactly `original + 1`.
Re-synchronisation is *exact*, not statistical. And the control's 0.20% is the same
arithmetic backwards: 4 MiB / 8 KiB = 512 boundaries, of which exactly one survives —
the end of the file — giving 1/512 = 0.195%. A control that returns precisely its
predicted value is what proves the measurement is sound rather than accidentally always
returning 100%.

---

## B4 🐛💾 Recovery deleted good data: one flipped byte destroyed a whole container

**The most serious defect found so far, and it was found by disbelieving a passing test.**

**Symptom.** A T6 test corrupted one byte inside a stored chunk and asserted the store
would notice. It failed in a confusing way -- not "corruption undetected" but:

```
CHECK(got.code() == Err::kCorrupt)     -- got kNotFound
CHECK_GT(v->problems, 0)               -- got 0
```

The chunk was not corrupt. The chunk was *gone*, and `verify()` called the store clean.

**Hypotheses.**
- (H1) The test's `dd` did not actually write where I thought, so nothing was corrupted.
  — *Rejected:* if nothing had changed, `get()` would have succeeded, not returned
  `kNotFound`. Something definitely happened to that chunk.
- (H2) The CRC check on read is not running, so `get()` missed the corruption and the
  `kNotFound` is unrelated. — *Rejected:* `kNotFound` comes from the index lookup, which
  is *before* any read. The chunk was missing from the index, not misread.
- (H3) Recovery removed it. — Correct, and far worse than it first looked.

**How I isolated it.** Wrote a 20-line probe that stored five chunks, corrupted one byte
inside the payload of the **first** one, reopened, and printed which chunks survived:

```
before: chunks=5
after corrupting record 0 of 5: chunks=0
  chunk 0 present: 0    chunk 1 present: 0    chunk 2 present: 0
  chunk 3 present: 0    chunk 4 present: 0
```

**All five.** One flipped byte in the first record destroyed the entire container, and
`verify()` reported no problems -- because there was nothing left to be wrong.

**Root cause.** `recover()` scanned records sequentially and, at the first record that
failed to parse, treated it as a **torn tail** and truncated the file there. Two entirely
different failures are indistinguishable to a sequential scanner:

| | what it is | correct response |
|---|---|---|
| **Torn tail** | crash partway through an append; nothing valid after it | truncate |
| **Mid-file damage** | bit rot, bad sector, stray write; valid records still follow | keep them, report the damage |

The code implemented the first response for both cases. The irony is that the fix was
already described in the codebase: `types.h` documents the per-record magic as
"a resynchronization point in a damaged file". That was a comment, not a mechanism.

**Fix.** On a record that does not parse, **resynchronize instead of guessing**: scan
forward for the next offset holding a record that fully validates (magic + in-range
length + payload present + CRC over that payload). Finding one *proves* this was not a
tail, so the damaged span is skipped and recorded rather than truncated away; finding
none means it really was a tail, and truncation is correct. A false resync would require
a 32-bit CRC collision on top of a 4-byte magic match. The scan is buffered in 1 MiB
windows with a 3-byte overlap so a magic straddling a window boundary is still found --
one `pread` per byte would be 128 million syscalls on a full container.

Two supporting changes, because the fix alone would still have been quiet:
- `ChunkStore::damage()` reports every skipped region (container, offset, length).
- `verify()` counts recovery damage as a problem. Without that, a store that had *lost
  records* still reported clean, which is how this bug hid in the first place.

After the fix, the same probe:

```
after corrupting record 0 of 5: chunks=4
  DAMAGE: container=0 off=0 len=4048
verify problems=1
```

**Generalizes to.** Three things:

- **A recovery path is code, and it is the least-tested code you own.** It runs only after
  something already went wrong, so its bugs are discovered at the worst possible moment.
  It deserves more adversarial testing than the happy path, not less.
- **When two different failures produce the same observation, you cannot pick a response
  by guessing -- you have to go get more evidence.** Here the evidence was one forward
  scan away, and the cost of not looking was silent data loss.
- **"Clean" from a verifier is only meaningful if the verifier can see what was lost.**
  A checker that inspects only what survived will always say the store is fine. That is
  not a bug in the store; it is a bug in the definition of the check.

---

## B5 🧱 The portability layer was written with a GNU extension

**Symptom.** `io.h` compiled but produced ten copies of:

```
warning: ISO C++ forbids braced-groups within expressions [-Wpedantic]
```

**Root cause.** The EINTR-retry helper was a macro using a statement expression,
`({ ... })` -- a GNU extension. `CMakeLists.txt` sets `CMAKE_CXX_EXTENSIONS OFF` with
the comment *"-std=c++20, never -std=gnu++20: portability is a claim we make"*. The file
whose whole job is to wrap platform quirks was itself written in a compiler-specific
dialect.

**Fix.** A function template instead: `eintr_retry([&] { return ::read(...); })`. Same
semantics, no extension, and it type-checks the retried expression rather than
textually pasting it.

**Generalizes to.** A warning that fires ten times is usually one decision, not ten
mistakes -- fix the decision. And when a project states a rule in a build file, the code
that is most likely to violate it is the code closest to the platform, which is exactly
where the rule matters most.

---

## B6 🌐 Every frame rejected: a protocol layer used a flag the wire contract never declared

**Symptom.** The first end-to-end test run failed at the very first frame, in all seven
tests at once:

```
REQUIRE(rr.stats.ok())                                          -- aborting test
REQUIRE(proto::send_blob(w, FrameType::kManifest, ...).ok())    -- aborting test
```

Nothing had been transferred. Every single write failed.

**Hypotheses.**
- (H1) The framing layer was broken -- it had been written by a different agent working in
  parallel and integrated without ever being exercised by this code. — *Rejected quickly,
  and it was the tempting one:* its own test suite passed, and a defect that broke EVERY
  write would have failed those too.
- (H2) A `MemoryLink` deadlock, since the target runs on another thread. — *Rejected:* the
  failure also occurred on the very first `write()`, before the target had done anything,
  and it was an error return rather than a hang.
- (H3) An argument the frame writer rejects. — Correct. "Every call fails identically"
  points at the *contract*, not at the machinery.

**How I isolated it.** Read `FrameWriter::write()` looking for what it validates rather
than what it does. Four lines in:

```c++
if ((flags & ~kKnownFrameFlags) != 0) return err(Err::kInvalidArgument, "unknown frame flag bits");
...
inline constexpr uint8_t kKnownFrameFlags = kFlagCompressed;
```

The protocol layer had invented `kFlagLastSlice = 1u << 1` to mark the final slice of a
manifest that spans several frames. The codec knew only about bit 0.

**Root cause.** An ownership seam. `types.h` declares the wire contract; `frame.h`
enforces it; `protocol.h` was written afterwards and added a flag bit to the *wire* while
only telling *itself*. The codec's strictness was correct -- reserved bits must be zero,
or they can never safely be assigned later -- so the bug was entirely on the side that
used an undeclared bit.

**Fix.** Declare the flag where the contract lives, not where it is used: `kFlagLastSlice`
moved into `types.h` beside `kFlagCompressed`, and `kKnownFrameFlags` became
`kFlagCompressed | kFlagLastSlice`. `protocol.h` now carries a comment saying where the
bit is defined and why it is not defined locally.

Deliberately NOT fixed by relaxing the check to allow unknown bits. That would have made
the symptom disappear and quietly destroyed the ability to add a flag later without
breaking older peers -- trading a loud five-minute bug for a silent compatibility one.

**Generalizes to.** Two things, and the second is about how this was built:

- **When every call fails identically, suspect the contract, not the code.** A machinery
  bug is usually input-dependent; a contract violation is uniform. That distinction cut
  the search from "read the whole framing layer" to "read its argument validation".
- **Parallel work needs the shared vocabulary to be owned by one place.** Four components
  were built concurrently against a written interface spec, and this is precisely the seam
  where that goes wrong: each side was individually correct and locally tested, and the
  disagreement existed only in the space between them. It surfaced at first integration,
  which is the cheapest moment it could have -- but the general lesson is that a
  constant shared across a boundary belongs in the header that DEFINES the boundary, and
  a layer that needs a new one has to go and add it there.

---

## B7 🐛⚔️ The fast resume path was slower than the fallback it was optimizing

**Symptom.** The first run of the T9 resume tests:

```
note: clean run 3012726 B; dropped run 1612273 + 3001220 = 4613493 B (53.1% overhead)
CHECK_GT(r->resumed_from, 0)   got: 0
```

A job that had already transferred half the tree resumed and re-sent **all of it**. And
the humiliating part is one line further down: the test that *deletes the session file*
and falls back to a full re-negotiation did better, skipping 142 of 332 chunks. The
optimization was losing to the thing it was optimizing.

**Hypotheses.**
- (H1) The resume handshake was not happening at all and the source silently ran a fresh
  job. — *Rejected:* `r->resumed` was true and `r->resumed_from` was 0. The fast path ran;
  it just resumed from the beginning.
- (H2) The checkpoint had never been written. — **True, and it was the first bug.**
  `kCheckpointBytes` is 8 MiB and the transfer was 3 MB, so the only checkpoint on disk
  was the initial one at zero. Any transfer smaller than one checkpoint interval resumed
  from scratch.
- (H3) Fixing H2 would fix the test. — **Wrong, and this is the interesting part.** I
  changed the target to rebuild its high-water mark by probing the store instead of
  trusting the checkpoint. The number improved (53% -> 52%) and the test still failed.
  Something else was dominating.

**How I isolated it.** H3 failing was the useful signal: if an accurate high-water mark
barely helped, then the high-water mark was the wrong abstraction. Looking at *why* it
stayed low: the source compresses batches on several threads, so **batches arrive out of
order**. The mark is deliberately CONTIGUOUS (a "highest seen" mark would skip gaps and
lose data), so a single missing early batch pins it near zero -- and the source then
re-sends every plan position above it, **including the hundreds of chunks the target
already had**. The mark was correct. Resuming *from* it was not.

**Root cause.** A design error, not a coding error. I had built resume around "keep the
original plan, remember how far it got, restart there", and then built machinery to
protect that idea -- persisting the manifest and need set so plan indices stayed stable
across a reconnect. All of that was solving a problem I had created. The plan does not
need to be stable, because the plan does not need to be remembered.

**Fix.** **Resuming is just re-negotiating without re-sending the manifest.** On
reconnect the target re-runs the set difference against its own store, which is
authoritative, and sends a fresh need set; both sides rebuild the plan from it. Everything
already received drops out regardless of what order it arrived in, regardless of when the
last checkpoint was written, and even if a chunk was lost to corruption since -- that one
is simply re-requested. What resume still saves is the expensive half: the manifest is
already on the target, so it is not sent again, and on a large tree that IS the cost
(SPEC 8.3).

That deleted the plan-stability requirement, the "restart at an index" logic, and the
reason the persisted need set existed -- rather than patching any of them.

**A second bug the same test exposed.** After the fix the numbers were better but the
session-deleted case still looked bad: only 55 of 332 chunks skipped, despite two thirds
of the transfer having gone out. That one was in the *test harness*: `MemoryLink` had an
unbounded in-flight queue, so the source raced arbitrarily far ahead of the target and the
injected abrupt close discarded a backlog no real socket would ever have been holding.
Giving it a 128 KiB capacity -- modelling an actual socket buffer -- took the skip count
from 55 to **203 of 332**.

**Results, before and after:**

| | before | after |
|---|---|---|
| drop mid-transfer, then resume | +53.1% over a clean run | **+8.7%** |
| `run_resilient` through 3 drops | 2.06x | **1.37x** |
| session deleted, fresh negotiation | 56% of a full transfer | **38%** |

**Generalizes to.** Three things:

- **When a fix produces a suspiciously small improvement, stop fixing and re-read the
  design.** H3 was a correct fix to a real bug that moved the number by 1%. That is
  evidence the model is wrong, not that the fix was too small.
- **An optimization that loses to its own fallback is not slow, it is wrong.** The
  fallback was doing the right thing all along -- asking the store what it actually has.
  The fast path had invented a second, worse source of truth. Deleting it made the system
  smaller AND faster, which is usually what happens when the extra state was never needed.
- **A test transport that is more permissive than the real one hides real behaviour.** An
  unbounded queue cannot exhibit backpressure, cannot show a writer outrunning a reader,
  and cannot deadlock -- so it cannot catch the bugs that depend on any of those. The
  fidelity of the fake decides what the test is capable of proving.

---

## B8 🐛 Two fault cases passed without injecting a fault

**Symptom.** The first faultrunner run was all green:

```
kill_after_chunk_fsync                     exited     yes       PASS
kill_after_manifest_fsync_before_commit    killed     yes       PASS
kill_after_commit_before_ack               exited     yes       PASS
6 cases run, 0 failed
```

Green, and wrong. Two rows say **`exited`** where the others say `killed`. Those children
finished normally. The cases named "kill the target here" never killed anything, and the
recovery path they exist to exercise was never entered.

Worth stating plainly: I only caught this because the runner prints HOW the child died.
Had it printed only PASS/FAIL, this would have shipped as two rows of decoration in the
matrix that backs a headline claim.

**Root cause (bug one).** Every injection site compared the returned kind against the one
kind it happened to know about:

```c++
if (WANREP_FAULT(FaultPoint::kAfterChunkFsyncBeforeManifest) == FaultKind::kIoError) ...
```

`check()` consumes the fire and returns the kind. Arming `kKillSelf` at a site that only
understood `kIoError` therefore burned the fire and did **nothing** -- silently, because
there is no way for `arm()` to know what the far-off call site will accept.

**Fix.** `kKillSelf` and `kStall` mean the same thing at every point, so they are handled
once, centrally, in `fault_check()`, and `WANREP_FAULT` routes through it. A site now only
interprets the kinds that are genuinely site-specific.

**Root cause (bug two), found immediately after fixing bug one.** With the kill actually
firing, the case failed differently: *"could not connect to the target"*. The injection
point lived inside `File::fsync()` -- and `File::fsync()` is called by
`write_file_atomic()`, which is called while creating the store's **superblock**. So a
fault armed for "after the chunk data is durable" fired during startup and killed the
child before it ever listened. The case would have been testing process startup.

**Fix.** Move the point to `ChunkStore::sync()`, the semantic moment it is named after.

**Generalizes to.** Three things:

- **A fault-injection test must assert that the fault FIRED**, not merely that the system
  survived. "Nothing went wrong" is the expected output of both a robust system and an
  inert test, and those must not look alike. The runner reports the child's death mode in
  every row for exactly this reason.
- **An injection point belongs at the moment it is named after, not at the lowest-level
  function on the path to it.** `File::fsync()` is on the path to "chunk data is durable",
  and also on the path to a dozen unrelated things. Naming a point after a semantic event
  and implementing it at a shared primitive means it fires in places nobody intended.
- **Where a value is produced far from where it is interpreted, put the shared meaning in
  the middle.** Each site independently remembering to handle each kind is a rule that
  cannot be enforced and will silently rot; `fault_check()` makes the common cases
  impossible to forget.

---

## B9 🐛 `try_push(T v)` ate the payload it refused to take

**Found by the adversarial review pass on the queues, in code that had already passed its
own test suite — and it was silently corrupting the replication pipeline.**

**Symptom.** None. Every test was green. The end-to-end suite replicated trees
byte-identically, `verify --deep` was clean, and the fault matrix passed.

**The defect.** Both queues declared `bool try_push(T v)` — **by value**. A bounded queue
forces every caller to write a retry loop, and the natural one is:

```c++
while (!q.try_push(std::move(v))) std::this_thread::yield();
```

On the first attempt `v` is **moved into the parameter**. The push is refused because the
queue is full, the parameter is destroyed, and every subsequent attempt pushes a
moved-from husk. In `protocol.h` that husk is an empty `std::vector<uint8_t>` — a batch of
chunk payloads that silently became zero bytes.

**Why nothing caught it.** The bug only fires when a queue is **full**, and in the tests
the queues never filled: T1 measured chunk+SHA-256 at 966 MB/s against a consumer that was
never the bottleneck at test sizes. The whole failure lives in the backpressure path,
which is the path that only matters under sustained load — i.e. in production.

**Fix.** `try_push(T&& v)`. An rvalue reference *binds* without consuming, so a refused
push leaves the caller's object intact and the obvious retry loop becomes the correct one.
The fix is in the queue, and `protocol.h` needed no change at all — which is the right
place for it: every future caller would have written the same loop and hit the same bug.

**Generalizes to.** **A fallible sink must not take ownership of what it refuses.** If a
function can say "no", its signature has to leave the caller holding the thing it still
owns. By-value is a promise to consume; a function that consumes on failure has a
signature that contradicts its contract, and no amount of care at the call site fixes it.
More generally: a bug that only manifests under backpressure will not appear in a test
whose queues never fill, so "the suite is green" says nothing about the saturated path.

---

## B10 🌐 An 11-byte reply could have killed the source process

**Found by the adversarial review pass on the wire protocol. Remotely reachable from an
unauthenticated peer (SPEC §8.7 says there is no authentication) — the highest-severity
defect in the project.**

**The defect.** `NeedSet::decode()` bounded the total number of indices like this:

```c++
len = len_minus_1 + 1;
if (len > kMaxNeedIndices - total) return err(Err::kTooLarge, ...);
```

With `len_minus_1 = 2^64 - 1`, `len` wraps to **0**. Zero is not greater than anything, so
the cap check passes, and the run "0 .. 2^64-1" — the entire index space — is accepted.
The eleven bytes `00 FF FF FF FF FF FF FF FF FF 01` are enough.

The run representation itself is compact, so the decode survives. The kill lands later:
`protocol.h` → `build_send_plan()` → `NeedSet::to_vector()`, which materializes 2^64
indices and takes the **source** process down by unbounded allocation. A malicious target
kills the machine that connected to it.

**Fix.** Do the arithmetic entirely in the domain that cannot wrap:
`if (len_minus_1 >= kMaxNeedIndices - total)`. Regression test verified to fail before and
pass after, plus neighbours proving it is a fix and not a special case: `UINT64_MAX - 1`
still rejected, a legal 2-index run at the very top of the space still accepted, and a run
exactly at the cap still legal.

**Generalizes to.** **`x + 1` is not a safe way to convert a length-minus-one, and the
overflow is invisible at the call site.** The check *looked* right — it named the cap, it
subtracted the running total, it returned the correct error code. Every part was correct
except the domain the arithmetic happened in. When a validator is written in terms of a
value derived from untrusted input, do the comparison on the raw value, not on something
computed from it.

And a note on where this was found: the building agent wrote a thorough suite, including
random fuzzing of the decoder. Uniform-random bytes essentially never produce a 10-byte
varint, so random fuzzing could not reach this input. It took a *structured* fuzzer that
deliberately emits well-formed varint pairs drawn from adversarial magnitudes. Random
fuzzing explores the middle of the input space; the bugs live at its edges.

---

## B11 ⚔️ The lock order I wrote down, violated in my own code

**Symptom.** With every suite otherwise green, TSan reported on `test_store`:

```
WARNING: ThreadSanitizer: lock-order-inversion (potential deadlock)
  Cycle in lock order graph: M0 => M1 => M0
```

**Root cause.** SPEC §3.6 states one global rule: `session mutex -> index shard ->
container writer`, never the reverse. Two functions disagreed about it:

- `recover()` held the container lock (`write_mu_`) and then took index shard locks to
  populate the index — **container → shard**.
- `verify()` held a shard lock while iterating and called `read_at()`, which takes the
  container lock — **shard → container**.

Either alone is fine. Together they are a cycle, and `verify()` is explicitly allowed to
run while a `rebuild_index()` is in progress, so it is reachable rather than theoretical.

Worth noting how it was caught: both stacks were on the **main thread**, at different
moments, in a test that never ran them concurrently. TSan builds a global lock-order graph
rather than waiting to observe an actual deadlock — which is why a deadlock that needs a
rare interleaving is findable at all.

**Fix.** Neither function needs to hold both.
- `recover()` collects `(fingerprint, location)` pairs during the scan and inserts them
  into the index **after** releasing the container lock.
- `verify()` snapshots each shard, releases it, and only then does file I/O — which also
  removes a shard lock held across a read, something `chunk_store.h`'s own comment already
  said not to do.

**Generalizes to.** **Writing the lock order down is necessary and nowhere near
sufficient.** I wrote that rule in the spec in T0, cited it in comments, and then broke it
in T6 in a function whose whole job is to run before anything is shared — which is exactly
the reasoning that makes it feel safe to break. The rule needs a *tool* enforcing it, and
TSan's lock-order graph is that tool: it found the cycle from two stacks that never ran at
the same time. Also: the fix in both cases was to hold *one lock instead of two*, which is
usually available and usually better than getting the order right.

---

## Open questions carried forward

- `WanLink`'s emulated RTT sits on top of a **2.6–10.2 µs** loopback baseline with p99
  excursions to 54 µs (§2.5). That is fine at 10 ms and above; it means a sub-millisecond
  emulated RTT would mostly be measuring the host. The RTT curve therefore starts at
  10 ms and labels its zero point "loopback", not "0 ms WAN".
- The 4 MiB `send()` that moved 6 144 bytes is the short-write proof. When `write_all()`
  is written in T5, the fault-injection layer must be able to reproduce *that* ratio —
  a `write_all` tested only against a socket that accepts everything is untested.
