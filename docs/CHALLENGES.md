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

## Open questions carried into T2+

- `WanLink`'s emulated RTT sits on top of a **2.6–10.2 µs** loopback baseline with p99
  excursions to 54 µs (§2.5). That is fine at 10 ms and above; it means a sub-millisecond
  emulated RTT would mostly be measuring the host. The RTT curve therefore starts at
  10 ms and labels its zero point "loopback", not "0 ms WAN".
- The 4 MiB `send()` that moved 6 144 bytes is the short-write proof. When `write_all()`
  is written in T5, the fault-injection layer must be able to reproduce *that* ratio —
  a `write_all` tested only against a socket that accepts everything is untested.
