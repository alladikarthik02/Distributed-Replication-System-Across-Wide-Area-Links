# `wanrep` — Technical Specification

**Project:** Distributed Replication System Across Wide-Area Links (C++)
**Scope:** a personal systems project; §2 maps every claim it makes to a testable requirement
**Status:** living document — edited as reality contradicts it (contradictions get logged in `CHALLENGES.md`)

---

## 0. How to read this document

- §1 says what this is and what it deliberately is not.
- §2 is the **claim contract**: every claim this project makes, mapped to a testable
  requirement. If a claim cannot be honestly satisfied by the finished code, the *claim*
  changes — not the measurement.
- §2.5 is the list of **environment facts we measured** rather than assumed.
- §3 is the architecture: the consistency contract, the wire protocol, delta negotiation, the
  in-tree compressor, the concurrency pipeline, resumable sessions, and the link emulator.
- §4 is the **essential function list** — the API/CLI surface that must exist for this to be the
  project described in §1.
- §5 is the **safety requirements** (S1–S17). This is the checklist to re-read at the end of every
  task: *"which of these did I just put at risk, and what proves I didn't break it?"*
- §6 is the testing strategy, §7 the task breakdown (the build order with explicit stop points),
  §8 the holes found by attacking this spec on purpose.

**Relationship to project #1 (`dedupe`).** These are separate repositories and separate claims.
`wanrep` carries over two files from `dedupe` verbatim — `sha256.h` and `crc32c.h`, with their test
suites — because they are pure, already verified against published vectors, and already have
runtime hardware dispatch. Everything else here is new: `dedupe` is about *storing* data once,
`wanrep` is about *moving* it once. The overlap in vocabulary (chunk, fingerprint, content
addressing) is real and is the point — content addressing is the mechanism that makes both
deduplication and delta replication work — but no code beyond those two headers is shared, and the
chunker is reimplemented here rather than borrowed, so this repository stands alone.

---

## 1. What we are building, and what we are deliberately NOT building

**Building.** A one-way, generational, chunk-level replication system in C++20 between two
processes — a **source** and a **target** — connected by a TCP link that we can make behave like a
wide-area link (high RTT, bounded bandwidth, abrupt disconnection):

- The source walks a directory tree, splits every file into **content-defined chunks**, and
  fingerprints each chunk with SHA-256. The result is a **manifest**: a generation-numbered,
  self-contained description of the tree.
- Source and target **negotiate**: the target reports which of those chunks it already holds. Only
  chunks the target is missing ever cross the link.
- Those chunk payloads are **compressed in transit** with an in-tree LZ77-family compressor, in
  batches, and never sent compressed when compression would make them larger.
- The target stores chunks in a content-addressed store and, once every needed chunk has arrived,
  **commits the generation atomically**. Until that commit, the new generation is invisible.
- A **dropped link or a killed node resumes** rather than restarting: the transfer picks up from
  the target's durable high-water mark, and anything already received is never re-requested.
- The hot path runs through a pipeline of threads connected by **lock-free bounded queues**, with
  the small amount of genuinely shared mutable state under **fine-grained locks** and a single
  documented lock order.

**NOT building (and why):**

| Not doing | Why |
|---|---|
| Multi-master / bidirectional replication with conflict resolution | The claim says "keeps data consistent across nodes," not "resolves concurrent writes." Conflict resolution (vector clocks, CRDTs, last-writer-wins) is a different project with a different failure model, and bolting on a token version would be decoration. One-way replication with a strict generational contract is a claim we can actually prove. |
| Consensus / quorum (Raft, Paxos) | Nothing here claims fault-tolerant agreement. A hand-rolled consensus protocol that is never model-checked is worse than none. |
| TLS, authentication, authorization | Not claimed. It would add an OpenSSL dependency and hide the framing and I/O-error behaviour we actually want to exercise. The threat model is stated in §8.7 instead of implied. |
| A general-purpose rsync clone (rolling-checksum delta *within* a chunk) | We deduplicate at chunk granularity, which is what the claim says. Byte-granular deltas inside a chunk would improve the ratio slightly and complicate resume enormously. Named as a known limit in §8.4. |
| Our own reliable transport over UDP | TCP already solves ordering, retransmission and congestion control, and rewriting it badly would make every measurement about our bugs instead of our design. We emulate WAN *conditions* on top of TCP (§3.8) and are explicit that this is emulation. |
| Deduplicated storage with garbage collection on the target | That is project #1. The target's chunk store here is append-only and never reclaims; space reclamation is `dedupe`'s claim, not this one. |

---

## 2. Claims → testable requirements (the contract)

The three claims this project makes, quoted as written, each followed by the requirements that
turn it into something testable.

> **R1.** "Built a C++ replication system that keeps data consistent across nodes over high-latency
> wide-area links, sending only changed chunks and compressing them in transit to reduce bandwidth
> use by about 60% versus full transfers."

| ID | Requirement | Proven by |
|---|---|---|
| R1.1 | Replication is **correct**: after a job completes, materializing the committed generation on the target yields the source tree byte for byte — contents, and the metadata we claim to replicate (path, mode, size). | `test_replicate`: round-trip property tests over randomized trees; whole-file SHA-256 recorded at scan and re-verified after materialization. |
| R1.2 | The target is **never inconsistent**, at any instant or after any failure: the set of visible generations is always a prefix of the source's committed generations, never a torn mixture. See **S2**. | `test_commit`: generation invisible until the commit record is durable; `tools/faultrunner` asserts the invariant after every injected failure. |
| R1.3 | Only **changed chunks** cross the link. A file unchanged since the last generation costs zero payload bytes; a one-byte edit costs ~one chunk. | `test_negotiate`: wire-byte counters assert payload bytes ≈ 0 for an unchanged tree and ≤ 2 chunks for a one-byte edit. The link layer counts the bytes, so this is measured, not modelled. |
| R1.4 | Chunk payloads are **compressed in transit**, and compression never inflates. | `test_compress` round-trip + adversarial fuzz; the raw-fallback rule is asserted on incompressible input. |
| R1.5 | ≈60% bandwidth reduction versus a full transfer, on a **defined, reproducible** workload. | `bench/gen_wan_corpus` + `bench/wire_bytes`; the workload model is printed with the number, always, together with the breakdown (unchanged-file skip vs chunk dedup vs compression) and two controls. See §8.1. |
| R1.6 | The system works over a **high-latency** link, and its throughput does not collapse as RTT grows. | `bench/rtt_curve`: throughput at 0/10/50/100/200 ms emulated RTT, plus **round trips per GiB**, which is the number that actually explains the curve (§3.2). |

> **R2.** "Handled concurrency with careful locking and lock-free queues on the hot path, and added
> resumable transfers so a replication job recovered cleanly from a dropped connection rather than
> restarting from the beginning."

| ID | Requirement | Proven by |
|---|---|---|
| R2.1 | The hot path uses **lock-free queues**: an SPSC ring and a bounded MPMC queue, both with no mutex in the uncontended push/pop path. | `test_queues`: single-threaded invariants + multi-producer/multi-consumer stress asserting **item conservation** (nothing lost, nothing duplicated, no ABA); run under TSan. |
| R2.2 | The lock-free choice is **justified by measurement**, not asserted. | `bench/queues`: our queues vs a `std::mutex` + condition-variable baseline at 1–8 producers; throughput and p99 push latency. If the lock-free version does not win, §8.5 says so and the claim changes. |
| R2.3 | Shared mutable state uses **fine-grained locking** with one documented global lock order and no deadlocks. | Lock order in §3.6, asserted in debug builds; full concurrency suite under TSan. |
| R2.4 | A **dropped connection resumes** rather than restarting: bytes re-sent after a drop are bounded by the checkpoint interval plus the in-flight window. | `test_resume`: drop the link at a randomized byte offset, reconnect, assert re-sent payload bytes ≤ bound and total wire bytes ≪ 2× the no-failure run. |
| R2.5 | A **killed target process** resumes: after `SIGKILL` and restart, the job continues and completes correctly. | `tools/faultrunner` kill-points; the target re-derives its high-water mark from durable state alone. |
| R2.6 | Memory is bounded and does not grow with dataset size — backpressure works. | `test_backpressure` with a hard RSS ceiling while replicating a tree far larger than the queue budget. |

> **R3.** "Validated consistency and recovery through fault-injection tests that dropped links and
> killed nodes mid-transfer, confirming the target stayed correct after every simulated failure."

| ID | Requirement | Proven by |
|---|---|---|
| R3.1 | Faults are injected at **named, enumerated points**, not randomly hoped for. | `include/wanrep/fault.h`: an injection registry; every point has an ID and appears in the test matrix report. |
| R3.2 | **Link drops** at every protocol phase leave the target correct. | `test_faults`: drop during HELLO, manifest, negotiation, mid-payload, between last chunk and commit, between commit and its ACK, and during the resume handshake. |
| R3.3 | **Node kills** (`SIGKILL`, no cleanup) at every phase leave the target correct. | `tools/faultrunner` forks a real target process and kills it at each point. |
| R3.4 | "Correct" is checked by a **single oracle** applied identically after every failure. | `wanrep target verify --deep` + materialize every committed generation + byte-compare against digests recorded by the source. Same oracle for all fault cases, so no failure gets a bespoke standard of proof. |
| R3.5 | Every fault case is **reproducible**: seeded, indexed, replayable by one command. | Seeds and injection IDs printed on failure; `faultrunner --case <id> --seed <n>`. |

**Integrity rule (carried over from previous projects):** if the finished system cannot hit a number
it states, we change the claim, not the measurement. Every claim in this project must be
reproducible by a stranger running one command in the container.

---

## 2.5 Verified environment facts (measured in T0, not assumed)

Everything below was *checked by a running test* on the target platform before any
dependent code was written. `tests/test_harness.cpp` is the proof, and it stays in the
suite so a future toolchain or kernel change that breaks one of these fails loudly.

The socket rows are the ones that matter most here, and they are the reason this project
does not reuse project #1's environment assumptions wholesale: a storage engine's
dangerous syscalls are `write` and `fsync`; a replication engine's are `send`, `recv`
and `close`, and **every one of them has a failure mode that looks like success.**

| Fact | Value | Why the spec depends on it |
|---|---|---|
| Target platform | Ubuntu 24.04, GCC 13, linux/**aarch64**, 8 CPUs (Docker on Apple silicon) | Everything below is measured here, not on macOS. |
| Byte order | little-endian | §3.2 and §3.5 read multi-byte fields by `memcpy`. On a big-endian host every length and sequence number would be byte-swapped — **and the magic would still match**, so the corruption would be silent. |
| `CHAR_BIT` / int widths | 8 / `uint64_t`=8 B / `uint32_t`=4 B | Every on-wire offset in §3.2 is stated in bytes. |
| `sizeof(FrameHeader)` | **32 bytes**, `alignof` 8, every field at its declared offset | The wire contract. Silent padding would desynchronise the two nodes at frame 1. Asserted at compile time *and* re-checked at runtime. |
| `sizeof(ChunkRecordHeader)` | **48 bytes**, `fp` at offset 16 | §3.5's record layout and its torn-tail recovery scan. |
| `std::atomic<uint32_t/uint64_t/size_t/void*>` | all **lock-free** | §3.6: if `std::atomic` fell back to a mutex for the Vyukov slot counter, "lock-free queues on the hot path" would be quietly false — the code would still compile and still be correct, and the headline claim would be a lie. |
| L1 cache line | **64 bytes** (`_SC_LEVEL1_DCACHE_LINESIZE`) | Sizes the padding that keeps the SPSC ring's head and tail off the same line. Sharing one line costs more than the mutex the queue was meant to replace. |
| One `send()` of 4 MiB | moved **6 144 bytes** | **The single most important fact in this document.** A naïve `send(fd, buf, len)` is a silent truncation bug: the frame is cut in half and the peer waits forever for a payload that will never arrive. Hence S11's rule that a `write_all()` loop is the *only* permitted way to touch a socket. |
| `recv()` of 100 bytes with 1 available | returns **1** | Same rule in the other direction: every header and payload read is a `read_exact()` loop. |
| Default `SIGPIPE` on a dead peer | **kills the process** (child died with signal 13) | A replication daemon that dies when a peer disconnects is not a replication daemon. Proven by forking a child that restores the default handler. |
| `send(..., MSG_NOSIGNAL)` on a dead peer | returns −1, `errno = EPIPE` | The mitigation. Turns process death into a handleable error, which is what makes "reconnect and resume" (§3.7) possible at all. |
| Orderly close (FIN) | `recv()` returns **0** | "The peer finished." |
| Abortive close (`SO_LINGER {1,0}` → RST) | `recv()` returns −1, `errno = ECONNRESET` (104) | "The peer **died**." §3.7's resume logic must distinguish these two; treating a RST like a clean 0 would commit a truncated transfer as if it were complete. This is exactly what a `kill -9`'d node looks like from the other side. |
| Blocking `recv()` + signal (no `SA_RESTART`) | returns −1, `errno = EINTR` | Without an explicit retry, a stray `SIGCHLD` from a fault-injection child turns into a spurious transfer failure — i.e. the test harness would create the bugs it is meant to find. |
| Loopback RTT baseline | p50 **2.6–10.2 µs**, p99 up to **54 µs** (25 runs × 500 samples) | The floor under `WanLink` (§3.8). Emulating a 10 ms RTT carries ≈0.5% noise, which is fine; emulating a *sub-millisecond* RTT would be mostly measuring this jitter, so §3.8's curve starts at 10 ms and the 0 ms point is labelled "loopback", not "0 ms WAN". |
| `steady_clock` granularity | ≈ **41 ns**, `is_steady` true | Every latency number in `BENCHMARKS.md` comes from this clock. |
| `rename()` over an existing file | replaces it; old name gone | How a manifest is published (§3.5). |
| `fsync()` on a directory fd | returns 0 | The directory entry is not durable until this runs — the classic way a file survives a crash under the wrong name. |
| `flock(LOCK_EX \| LOCK_NB)`, second open — **on `/tmp` (overlayfs)** | fails `EWOULDBLOCK` | S16. Locks attach to the open file description, so two independent `open()` calls contend even within one process. |
| `flock(LOCK_EX \| LOCK_NB)`, second open — **on `/work` (virtiofs bind mount)** | **SUCCEEDS. Exclusion is silently broken.** | Found by attacking the previous row instead of trusting it (`CHALLENGES.md` B2). A target store on the bind-mounted host directory — the most natural place a user would put one — has **no** S16 enforcement and no diagnostic. This is why `fsprobe.h` ships and why the store refuses to open where the probe fails, and why every test store lives on container-local storage. |
| `rename`, `fsync(file)`, `fsync(dir)`, `fdatasync(dir)` on **both** filesystems | all succeed | The commit path (§3.5) works on either; only locking differs. Checked on both rather than generalised from one. |
| Suite determinism | **25/25 runs green**, zero flakes | Checked deliberately before building anything on top: a fault-injection project whose baseline suite flakes cannot tell an injected failure from a bad test. |


---

## 3. Architecture

### 3.0 The one idea

**Content addressing turns a network problem into a set-difference problem, and turns crash
recovery into a no-op.**

Every chunk is named by the SHA-256 of its own bytes. Three consequences carry the entire design:

1. **"What has changed?" becomes "which names do you not have?"** — a question the target can
   answer locally, without the source telling it anything about history. No file timestamps to
   trust, no journal to ship, no rename detection: content that already exists on the target is
   never sent, whatever file it now lives in.
2. **Every transfer is idempotent.** Re-sending a chunk the target already has is a no-op, not a
   corruption. That is what makes resume safe *by construction* rather than by careful bookkeeping.
3. **The receiver never has to trust the sender.** The target recomputes the fingerprint of every
   chunk it receives and refuses any chunk whose bytes do not hash to its claimed name. A buggy
   source, a corrupted frame, and a hostile peer are all the same case, handled the same way.

And one deliberate echo of project #1's central decision: **durability is kept out of the
correctness path.** The resume checkpoint, the session journal, and the target's chunk index are
all *performance* artifacts. If every one of them is lost, the system is still correct — it just
re-negotiates and re-sends some chunks. The only durable thing that correctness depends on is the
generation commit record. Making that list as short as possible is the whole trick.

```
   SOURCE                                                        TARGET
   ──────                                                        ──────
   scan tree
      │  paths
      ▼
   ┌──────────────┐  chunk + SHA-256           HELLO / HELLO_ACK
   │ chunkers × N │ ─────────────┐          ◄──────────────────────►
   └──────────────┘              │
      │ manifest (gen G)         │             MANIFEST ─────────►  diff vs gen G-1
      ▼                          │                                  probe chunk index
   canonical chunk list          │          ◄───────── NEED (RLE)   (the set difference)
      │                          │
      ▼                          ▼
   ┌──────────────┐  lock-free  ┌──────────────┐
   │  send plan   │ ──ring────► │ compressors  │
   └──────────────┘             └──────┬───────┘  batched LZ blocks
                                       │ MPMC
                                       ▼
                                ┌──────────────┐   CHUNKS[seq] ──►  verify CRC
                                │ sender (owns │                    verify SHA-256   ← never trusts
                                │  the socket) │                    append to store     the sender
                                └──────────────┘                    advance high-water
                                       │
                                       │          ◄──── CHECKPOINT (contiguous high-water)
                                       │
                                       │           GEN_COMMIT ───►  fsync chunks
                                       │                            write manifest (tmp→fsync→rename→fsync dir)
                                       │                            append COMMIT record, fsync   ← the only
                                       │          ◄─── COMMIT_ACK      durable thing correctness needs
                                       ▼
                                 generation G replicated
```

### 3.1 System model and the consistency contract

**Model.** One source, one target, one dataset (a directory tree), one direction. The source
produces **generations** G = 0, 1, 2, … Each generation is a complete, self-contained manifest of
the tree at one point in time — not a diff. (Deltas are computed during negotiation, not stored;
this means a target can be brought current from any starting state, including empty, without a
chain of deltas that must all survive.)

**The contract, stated so it can be attacked:**

> **C1 — Prefix consistency.** At every instant, and after any combination of link drops and node
> kills, the set of generations visible on the target is `{0, 1, …, k}` for some k ≤ the source's
> latest committed generation. Never a proper subset with a hole, never a partially applied
> generation, never a mixture of two generations' file contents.

> **C2 — Generation fidelity.** For every visible generation k, materializing it on the target
> produces a tree byte-identical to the source tree as it was when the source scanned generation k.

C1 is what "keeps data consistent across nodes" means operationally, and it is enforced by exactly
one mechanism: a generation becomes visible when — and only when — its COMMIT record is durable in
the target's generation journal (§3.5). Everything transferred before that point is inert: chunks
in a content-addressed store that nothing references yet.

**What we do not claim.** We do not claim the target is a *synchronous* replica; it lags by up to
one generation, which is what asynchronous WAN replication is. We do not claim the source tree is
frozen during a scan — if a file changes while being scanned, generation G captures a torn version
of *that file*, and the honest statement is C2's "as it was when the source scanned it." Real
systems solve this with a filesystem snapshot underneath; that is out of scope and named here
rather than quietly assumed (§8.2).

### 3.2 The wire protocol — and why round trips, not bytes, are the WAN enemy

**The arithmetic that shapes the protocol.** A wide-area link is defined by its
*bandwidth-delay product*. At 100 Mbit/s (12.5 MB/s) with a 100 ms round trip, the BDP is
**1.25 MB** — that much data must be in flight at all times just to keep the link busy. A protocol
that asks "do you need this chunk?" and waits before sending it moves one 8 KiB chunk per round
trip: 8192 B / 0.1 s ≈ **82 KB/s**, or 0.65% of the link. The same protocol on loopback would look
perfect. This is the single most common way a replication design that benchmarks well locally dies
on a real WAN, and it is why §3.3's negotiation is **one batched exchange per generation**, not one
per chunk, and why payload frames are **streamed without per-chunk acknowledgement**.

Consequence for the metrics: `bench/rtt_curve` reports **round trips per GiB** alongside
throughput, because that ratio — not the byte count — is what predicts behaviour at an RTT we did
not test.

**Frame format (32-byte header + payload), little-endian:**

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `magic` = `'W','R','P','1'` — protocol id + version; also a resynchronization point |
| 4 | 1 | `type` — see table below |
| 5 | 1 | `flags` — bit 0: payload is compressed |
| 6 | 2 | `reserved` (must be zero; rejected otherwise, so it stays available) |
| 8 | 4 | `wire_len` — payload bytes actually on the wire |
| 12 | 4 | `raw_len` — payload bytes after decompression (== `wire_len` when not compressed) |
| 16 | 8 | `seq` — plan sequence number for `CHUNKS`, else 0 |
| 24 | 4 | `payload_crc` — CRC32C of the **on-wire** payload bytes |
| 28 | 4 | `header_crc` — CRC32C of bytes 0..27 |

**Why the header carries its own CRC, separate from the payload's.** To read a frame you must first
trust `wire_len` — you are about to read that many bytes and allocate a buffer of that size. If the
header is corrupt, a payload CRC cannot help you: you have already used the bad length. So the
header is validated against `header_crc` **before any field in it is used**, and `wire_len` and
`raw_len` are then range-checked against `kMaxFrame` (1 MiB) **before a single byte is allocated**.
This is safety requirement **S7**, and it is the difference between "a corrupt frame is an error"
and "a corrupt frame is a 4 GiB allocation."

**Frame types and the phases they belong to:**

| Type | Direction | Phase | Meaning |
|---|---|---|---|
| `HELLO` / `HELLO_ACK` | S→T / T→S | handshake | Protocol version, capabilities, dataset name. Version mismatch fails cleanly here and nowhere else. |
| `SESSION_START` | S→T | handshake | New job: dataset, generation, manifest digest. Target allocates a session id. |
| `SESSION_RESUME` | S→T | handshake | Existing job by id; target replies with its durable high-water mark, or `NOT_FOUND` (§3.7). |
| `SESSION_ACK` | T→S | handshake | Session id + high-water mark. |
| `MANIFEST` | S→T | negotiation | The generation's manifest, streamed across as many frames as needed. |
| `NEED` | T→S | negotiation | Run-length-encoded indices into the canonical chunk list (§3.3). |
| `CHUNKS` | S→T | transfer | A compressed batch of chunk payloads, tagged with a plan `seq`. |
| `CHECKPOINT` | T→S | transfer | Contiguous high-water mark; advisory, sent periodically. |
| `GEN_COMMIT` | S→T | commit | All needed chunks sent; please commit generation G. |
| `COMMIT_ACK` | T→S | commit | Commit record is durable. Only now is the generation replicated. |
| `ERROR` | either | any | Code + message. A node that cannot continue says so instead of hanging up silently. |
| `BYE` | either | teardown | Orderly shutdown, so `read()==0` means "finished" and not "died" (§2.5). |

**Framing rules.** Every frame is self-delimiting and every payload is CRC-checked. `kMaxFrame` is
1 MiB, which bounds receiver memory per connection regardless of what the peer claims. A frame that
fails any check terminates the connection with an `ERROR` rather than being skipped — a
resynchronization heuristic on a stream we cannot trust is how a corrupted transfer silently
becomes a corrupted replica.

### 3.3 Delta negotiation — how "only changed chunks" actually works

Two levels, cheapest first.

**Level 1 — unchanged files cost nothing.** The manifest for generation G is diffed by the target
against its manifest for generation G−1. A file whose path, size, mode, mtime **and whole-file
SHA-256** all match is skipped entirely; none of its chunks are even probed. (The digest is in the
comparison on purpose: mtime and size agreeing is a heuristic, and heuristics are how backup tools
silently miss changed data.)

**Level 2 — the set difference over chunks.** For every remaining file, the target probes its local
chunk index for each fingerprint. Missing fingerprints become the request. Because the index covers
*every chunk the target has ever stored*, this automatically handles the cases a file-level diff
cannot: a renamed file (same chunks, new path) sends nothing; a file assembled from pieces of other
files sends nothing; a 1-byte edit sends the one or two chunks whose content-defined boundaries
moved.

**The canonical chunk list — why both sides can agree on a numbering without exchanging one.**
Both sides derive, deterministically from the manifest alone, the same ordered list: walk files in
manifest order, walk each file's chunks in order, and append each fingerprint the first time it is
seen. That gives indices `0 … M−1`, identical on both nodes, computed independently. The target's
`NEED` reply is therefore just a set of integers, run-length encoded — for a mostly-unchanged tree
it is a handful of bytes describing millions of chunks it does not need.

The **send plan** is the needed indices in ascending order, and a chunk's position in that plan is
its `seq`. This is the detail that makes resume cheap: `seq` is assigned at *plan* time, not at
send time, so it is stable across a disconnect and across the source's own thread scheduling. The
sender threads may emit frames out of order; the target tracks a **contiguous** high-water mark over
`seq` plus a small out-of-order window, and resume restarts at the contiguous mark. Some already-
received chunks get re-sent; they are idempotent, the amount is bounded by the window, and it is
measured (R2.4).

**Cost of the negotiation itself.** One manifest transfer plus one `NEED` reply — **two round
trips** per generation, independent of dataset size. The manifest is the real cost: ~36 bytes per
chunk (32-byte fingerprint + 4-byte length) ≈ 0.44% of logical size at 8 KiB chunks. §8.3 is honest
about what that means for the bandwidth claim, because on a nearly-unchanged tree the manifest is
the *dominant* cost, and pretending otherwise would inflate the headline number.

### 3.4 In-transit compression — an LZ77-family compressor, in-tree

**Why in-tree, not zlib.** Same rule as project #1: no hidden dependencies, and a compressor whose
decoder we wrote is a compressor whose decoder we can prove is bounds-safe. This matters more than
usual here: the decompressor is the code that runs on **attacker-controlled bytes arriving from the
network**, and the LZ77 family's decoder is a well-known source of buffer-overflow CVEs (a match
instruction that says "copy 64 KB from 60 KB back" runs off both ends if you trust it).

**Format.** An LZ4-style block: a token byte splitting literal length (high nibble) and match length
(low nibble, biased by 4), optional 255-extension bytes for either length, the literal bytes, then a
2-byte little-endian match offset. Compression uses a 64 K-entry hash table over 4-byte sequences —
one probe, no chaining, no entropy coding stage. The design point is **throughput**, not ratio: a
compressor that cannot keep up with the link is a bandwidth *reduction* that costs you bandwidth.

**Three rules that are safety requirements, not optimizations:**

1. **Never expand.** If the compressed block is not smaller than the input, the batch is sent raw
   with the compressed flag clear. Without this rule, incompressible data (already-compressed
   media, encrypted files, random bytes) makes the "bandwidth reduction" negative. **S14.**
2. **The decoder validates every instruction before executing it.** Literal length must fit in the
   remaining input; match offset must be ≥1 and ≤ bytes already produced; match length must fit in
   the remaining output. A violation is an error return, never a truncated copy and never UB. The
   decoder also refuses to produce more than `raw_len` bytes, which the frame header already
   bounded. **S14.**
3. **Compress batches, not chunks.** An 8 KiB chunk compressed alone wastes the dictionary; a
   ~256 KiB batch of consecutive chunks lets the matcher find cross-chunk redundancy, which is
   common in backup data. The batch size is a tuned parameter with a measured curve, not a guess.

**What we will report.** Ratio on each content class in the corpus (text-like, structured binary,
incompressible), compression and decompression throughput in MB/s, and the batch-size curve. The
headline bandwidth number in §8.1 always separates savings from *skipping* from savings from
*squeezing*, because those two are different engineering claims and only one of them is about the
compressor.

### 3.5 Target-side storage layout

```
<target-store>/
  TARGET                superblock: magic, version, store uuid, chunk params
  LOCK                  flock'd for the lifetime of the target process       (S16)
  chunks/
    c00000001.dat       append-only, self-describing chunk records
  index/                (rebuildable cache; see below)
  datasets/<name>/
    manifests/
      g0000000007.man   one per generation, written tmp → fsync → rename → fsync(dir)
    GENERATIONS         append-only journal of COMMIT records — the ONLY authority
  sessions/
    <session-id>.ses    resume checkpoints (performance only, never correctness)
```

**Chunk record (48-byte header + payload):** `magic` (4) · `length` (4) · `crc32c` (4) · `flags` (4)
· `fp` (32). Self-describing on purpose: the chunk index is rebuildable by scanning `chunks/`, and a
torn tail from a `kill -9` mid-append is detectable — recovery truncates at the first record whose
header is short, whose magic is wrong, or whose CRC fails.

**`GENERATIONS` is the single source of truth for visibility.** A manifest file that exists but is
not named by a durable COMMIT record does not exist as far as any reader is concerned; recovery
deletes it. This is what makes C1 true with one `fsync` instead of a distributed protocol:

```
  all needed chunks received
     → fsync chunk containers                  (data durable)
     → write manifest tmp, fsync, rename, fsync(dir)   (manifest durable but INVISIBLE)
     → append COMMIT{gen, manifest digest} to GENERATIONS, fsync   ← the atomic instant
     → reply COMMIT_ACK                        (source may now advance)
```

Crash before the COMMIT record → generation invisible, chunks are inert garbage, source retries and
re-sends almost nothing (the chunks are already there). Crash after the COMMIT record, before the
ACK → generation *is* visible, the source retries, the target replies "already committed." Both
paths are idempotent, which is the property every recovery path in this system is required to have.

### 3.6 Concurrency — the pipeline, the queues, and the lock order

**The pipeline (source side).** Work moves forward through bounded queues; no stage ever waits on a
stage behind it.

```
  scanner ──► [SPSC ring] ──► chunker+hasher × N ──► [MPMC] ──► compressor × M ──► [MPMC] ──► sender
  (1 thread)   per worker      (CPU-bound: SHA-256)              (CPU-bound: LZ)            (1 thread,
                                                                                          owns socket)
```

- **One sender thread owns the socket.** This removes the need for any lock around `write()` and
  guarantees frames are never interleaved. It costs nothing: a single thread saturates a WAN link
  by a wide margin, since the expensive work (hashing, compressing) already happened upstream.
- **Chunking and hashing are the CPU bottleneck of the source**, which is why they fan out to N
  workers — but T1 measured how much headroom there actually is, and the honest answer changes the
  emphasis. Chunking alone runs at **1 855 MB/s**; chunking *plus* SHA-256 fingerprinting, which is
  the real per-byte cost, runs at **966 MB/s** on one thread. A 100 Mbit/s WAN link is 12.5 MB/s, so
  a single thread covers it **77×** over, and even a 1 Gbit/s link needs 13% of one core.
  **Therefore:** the fan-out is not what makes the WAN case work — one thread already does. It earns
  its place for LAN- and loopback-speed runs, where the pipeline's shape is actually visible, and for
  the compressor stage, which is the slower one. This is written down here rather than left implied,
  because "we parallelised the hot path" is only worth saying next to the number that shows what the
  hot path could already do. See §8.5.

**The queues (R2.1).**

| Queue | Type | Where | Why this one |
|---|---|---|---|
| `SpscRing<T>` | bounded, single-producer single-consumer | scanner → each chunker | The cheapest correct queue that exists: producer touches only the head, consumer only the tail, one `release` store and one `acquire` load per item, no CAS at all. Head and tail are on separate cache lines, because sharing one line makes two threads fight over it and costs more than a mutex would. |
| `MpmcQueue<T>` | bounded array with per-slot sequence numbers (Vyukov) | chunkers → compressors → sender | Multiple producers need atomicity on the tail; a per-slot sequence counter gives that with one CAS on the position and one `release` store on the slot, and the monotonically increasing 64-bit counters make ABA impossible rather than unlikely. |

**Honesty about "lock-free" (this is the part that gets challenged in an interview).** These queues
are lock-free on the **hot path** — an uncontended push or pop executes no lock and cannot be
blocked by a descheduled peer. They are **bounded**, so a producer facing a full queue must do
something, and what it does is spin briefly and then block on a condition variable. That waiting
path is not lock-free and is not claimed to be: it is backpressure, and backpressure is the feature
that keeps memory bounded (R2.6, S10). The project claims "lock-free queues on the hot path," and that
is exactly and only what is being claimed. `bench/queues` measures both against a mutex baseline,
and if the lock-free version does not win at our producer counts, §8.5 records that and the bullet
changes.

**Fine-grained locking (R2.3).** The genuinely shared mutable state is small and each piece has its
own lock:

| State | Lock | Granularity |
|---|---|---|
| Target chunk index | `std::shared_mutex` × 256 shards, keyed on the fingerprint's top byte | Readers (negotiation probes) share; writers (chunk stored) take one shard briefly. |
| Chunk container writer | one mutex per open container | Only the append is serialized, not the hashing or verification before it. |
| Session table | one mutex | Touched once per connection, never on the hot path. |
| Generation journal | one mutex | Touched once per generation. |

**Lock order — one global rule:** `session mutex` → `index shard` → `container writer`. Never the
reverse, and **never two index shards at once**. Violations are deadlocks, so this is asserted in
debug builds rather than trusted to code review.

### 3.7 Resumable transfers

**The mechanism.** The target maintains, per session, a **contiguous high-water mark** over plan
`seq` — the largest `h` such that every chunk with `seq < h` has been durably stored. Out-of-order
arrivals sit in a small bitmap window until they become contiguous. The mark is checkpointed to
`sessions/<id>.ses` (fsynced) every `kCheckpointBytes`, and sent to the source as an advisory
`CHECKPOINT` frame.

**On reconnect,** the source sends `SESSION_RESUME(session_id)`:

- **Fast path** — the target knows the session: it replies with the durable high-water mark and the
  source resumes at that plan index. One round trip, no re-negotiation, no re-scan.
- **Fallback** — the session is unknown, the checkpoint is stale, or the manifest digest does not
  match: the target replies `NOT_FOUND` and the source re-runs negotiation from §3.3.

**Why the fallback is not a restart, and this is the important part.** Re-negotiation asks the
target which chunks it needs *now* — and the chunks that already arrived are in its store, so it
does not ask for them again. The work lost is one manifest exchange (two round trips), not the
transfer. **Resume therefore does not depend on the checkpoint being correct, or existing at all.**
The checkpoint saves two round trips; content addressing saves the data. That is the §3.0 principle
paying for itself, and it is why `test_resume` includes a case that deliberately deletes the session
file before reconnecting and still asserts that almost nothing is re-sent.

**Bounded re-send.** After a fast-path resume, the bytes re-sent are at most
`kCheckpointBytes + in-flight window`. That bound is asserted, and the measured value is reported.

### 3.8 The WAN link emulator and fault injection

Real wide-area conditions are not reproducible, and a test that depends on the internet is not a
test. So `Link` is an interface with three implementations:

| Implementation | Purpose |
|---|---|
| `TcpLink` | A real socket. What ships. |
| `WanLink` | Wraps `TcpLink`; adds a fixed RTT, a bandwidth ceiling (token bucket), and optional jitter. Deterministic given a seed. |
| `FaultLink` | Wraps either; drops the connection, injects errors, or corrupts bytes at a **named injection point**. |

**What we emulate, and what we honestly do not.** We emulate latency, bandwidth limits and abrupt
disconnection — the three properties the project's claims actually depend on. We do **not** emulate
packet loss or reordering, because those live below TCP and injecting them above it would be
theatre. Byte corruption *is* injected, not because TCP checksums fail often, but because the frame
CRCs are a claim we make and an untested check is not a check. The container also has `tc netem`
available for an optional real-kernel latency check, which is a cross-validation of `WanLink`, not
a replacement for it.

**Fault injection points** are registered by name and enumerated, so the test matrix is a list of
IDs rather than a hope: `after_hello`, `mid_manifest`, `after_manifest`, `after_need`,
`mid_payload_early`, `mid_payload_late`, `before_commit`, `after_manifest_fsync_before_commit`,
`after_commit_before_ack`, `mid_resume_handshake`, and their `kill -9` twins. §7's T10 is where the
matrix is filled in and reported.

---

## 4. Essential functions — the required surface

If any of these is missing, this is not the project described in §1.

### 4.1 Library API (`include/wanrep/`)

| Function | Contract |
|---|---|
| `sha256(span) → Digest32`, `Sha256::update/final` | Matches NIST FIPS-180-4 vectors; scalar and ARMv8 backends agree bit-for-bit. Carried from project #1. |
| `crc32c(span)` | Matches published vectors; used on every frame header, frame payload and chunk record. |
| `Chunker::next(span) → optional<Chunk>` | Streaming FastCDC/Gear; respects Min/Avg/Max; deterministic for identical input; identical boundaries on both nodes. |
| `Lz::compress(src, dst) → size_t` / `Lz::decompress(src, dst_cap) → Result<size_t>` | Round-trips exactly; never expands (raw fallback above); decoder is bounds-safe on hostile input and returns errors rather than trapping. |
| `SpscRing<T>::try_push/try_pop`, `MpmcQueue<T>::try_push/try_pop` | Bounded, lock-free on the uncontended path; item-conserving under concurrency; explicit failure on full/empty (no blocking inside the queue itself). |
| `Link` (`read/write/close/bytes_in/bytes_out`) | The transport interface. **`bytes_out` is the authoritative wire-byte counter** — every bandwidth claim in this project is read from here, not modelled. |
| `TcpLink`, `WanLink(rtt, bw, seed)`, `FaultLink(points)` | Real socket; emulated WAN; injectable failures (§3.8). |
| `FrameWriter::write(type, seq, payload)` / `FrameReader::next() → Result<Frame>` | Header CRC validated before any header field is used; `wire_len`/`raw_len` range-checked before allocation (S7). |
| `Manifest::scan(tree) → Manifest`, `Manifest::encode/decode` | Deterministic ordering; carries path, mode, size, mtime, whole-file digest, chunk list. |
| `canonical_chunk_list(Manifest) → vector<Digest32>` | Deterministic first-occurrence ordering; **both nodes must compute the identical list** (differential-tested). |
| `Negotiator::need(manifest, prev_manifest, index) → NeedSet` | The set difference of §3.3; run-length encodes to the wire. |
| `ChunkStore::put(fp, bytes)` / `get(fp) → bytes` | Verifies CRC **and** recomputes SHA-256 before storing (the target never trusts the sender, S17); append-only; torn tails recovered on open. |
| `ChunkIndex::insert/lookup`, `rebuild_from_containers()` | Sharded; a rebuildable cache, never an authority. |
| `ManifestStore::commit(gen, manifest)` / `visible_generations()` | The atomic-visibility mechanism of §3.5; commit is durable before it returns. |
| `SessionJournal::checkpoint(seq)` / `recover(id) → high_water` | Performance only; correctness must hold when it is deleted. |
| `SourceJob::run(link, tree, dataset) → JobStats` | Scan → manifest → negotiate → pipeline → commit; returns wire bytes, payload bytes, chunks sent/skipped, round trips. |
| `TargetServer::serve(link)` | One connection, all phases, resumable; never trusts a length, a digest or a peer. |
| `Verifier::verify(store, Level) → VerifyReport` | **The oracle.** Every committed generation's manifest resolves; every chunk's CRC and fingerprint match its bytes; no manifest references a missing chunk; no uncommitted manifest is visible. Used identically by every fault test (R3.4). |

### 4.2 CLI (`wanrep`)

```
wanrep target serve   --store <dir> --listen <host:port>
wanrep target ls      --store <dir> [--dataset <name>]
wanrep target materialize --store <dir> --dataset <name> --gen <n> --out <dir>
wanrep target verify  --store <dir> [--deep]
wanrep source replicate --tree <dir> --peer <host:port> --dataset <name>
                        [--rtt <ms>] [--bw <MB/s>] [--resume <session-id>]
wanrep bench <subcommand>
```

### 4.3 Tools

| Tool | Purpose |
|---|---|
| `bench/gen_wan_corpus` | The reproducible multi-generation dataset of §8.1, from a seed. |
| `bench/wire_bytes` | The headline bandwidth number **and its breakdown** (skip vs dedup vs compression vs protocol overhead). |
| `bench/rtt_curve` | Throughput and round-trips-per-GiB at 0/10/50/100/200 ms emulated RTT (R1.6). |
| `bench/queues` | Lock-free queues vs a mutex+condvar baseline, 1–8 producers (R2.2). |
| `bench/lz` | Compression ratio per content class, compress/decompress MB/s, batch-size curve. |
| `tools/faultrunner` | Forks a real target process, injects a named fault, restarts, resumes, runs the oracle (R3.3). |

---

## 5. Safety requirements — the checklist to re-read after every task

Each item: **what must never happen**, **how it is enforced**, **what proves it**.

| ID | Invariant | Enforcement | Proof |
|---|---|---|---|
| **S1** | **Replicated data is never wrong.** A materialized generation equals the source tree byte for byte. | Per-chunk CRC32C **and** SHA-256 recomputed on receipt; whole-file digest recorded at scan and re-verified after materialization; any mismatch is a hard error, never a warning. | Round-trip property tests over randomized trees (empty files, 1-byte, exactly Min/Avg/Max chunk sizes, sparse, deeply nested paths); `verify --deep`. |
| **S2** | **A generation is never partially visible.** Contract C1 (§3.1). | Visibility is defined solely by a durable COMMIT record in `GENERATIONS`; manifests are written and fsynced *before* the record and are inert until named by it; recovery deletes unnamed manifests. | `test_commit` + the full fault matrix: after every injected failure the visible set must be a prefix, checked by the oracle. |
| **S3** | **A crash never corrupts the target store.** After `SIGKILL` at any point, the store opens and every *committed* generation is intact. | Self-describing chunk records + CRC → torn tails detected and truncated; append-only journal with idempotent replay; index rebuildable by scanning containers. | `tools/faultrunner` at every kill point × N iterations, each followed by open + `verify --deep` + materialize-all. |
| **S4** | **Nothing is acknowledged before it is durable.** | Chunk containers fsynced before the manifest is renamed; manifest fsynced (and its directory fsynced) before the COMMIT record; COMMIT record fsynced before `COMMIT_ACK` is written to the socket. | Ordering asserted by a fault-injection I/O layer that fails at each sync boundary; kill points sit on both sides of every one of those boundaries. |
| **S5** | **A dropped link never loses or duplicates applied data.** | Chunks are content-addressed and idempotent; the high-water mark is contiguous, not "highest seen"; commit is idempotent (a repeat `GEN_COMMIT` for an already-committed generation returns success without rewriting). | `test_resume` drops at randomized offsets; the oracle runs after each. |
| **S6** | **A resumed job never restarts from the beginning.** | Fast path resumes at the durable high-water mark; the fallback re-negotiates, and the set difference excludes everything already stored. | `test_resume` asserts re-sent payload bytes ≤ `kCheckpointBytes + window`, **and** a case that deletes the session file entirely and still asserts ≪ full re-send. |
| **S7** | **A hostile or corrupt frame never causes a large allocation, an overflow, or a crash.** | `header_crc` validated before any header field is used; `wire_len`/`raw_len` range-checked against `kMaxFrame` before allocation; every payload length re-validated against bytes actually read. | `test_frame_fuzz`: random and mutated frames under ASan+UBSan; every case must yield a clean error. |
| **S8** | **No data races, no deadlocks.** | Fine-grained locks with one documented global order (§3.6); never two index shards at once; debug-build lock-order assertions. | Full concurrency and end-to-end suites under TSan. |
| **S9** | **The lock-free queues are actually correct.** No lost items, no duplicated items, no ABA, no torn values. | Bounded ring with power-of-two masking and acquire/release pairs; Vyukov per-slot sequence counters (64-bit, monotonic → ABA impossible, not merely unlikely). | `test_queues`: item-conservation stress (every produced item consumed exactly once, verified by a checksum over payloads), N producers × M consumers, under TSan. |
| **S10** | **Memory stays bounded and predictable**, independent of dataset size. | Every queue is bounded; producers block on backpressure; files are streamed, never loaded whole; per-connection receive memory bounded by `kMaxFrame`. | `test_backpressure`: replicate a tree far larger than the queue budget under a hard RSS ceiling. |
| **S11** | **No silent failure.** Every syscall checked; short writes and partial reads handled; `EINTR` retried; `SIGPIPE` suppressed so a dead peer is an errno, not a dead process. | `Result<T>` on every I/O path; `-Werror=unused-result`; a `write_all`/`read_exact` pair that is the *only* way the codebase touches a socket. | The socket-behaviour facts in §2.5 are re-checked by `test_harness`; fault-injection fails the Nth op of each kind and the node must surface an error, not hang. |
| **S12** | **A hostile peer never gains control of a node.** | Every length, count, offset and path from the wire is validated before use; manifest paths are rejected if absolute, containing `..`, or escaping the target root; no `system()`, no path concatenation without validation. | `test_manifest_hostile`: crafted manifests with `../`, absolute paths, symlink targets, absurd counts, and negative-looking sizes. |
| **S13** | **The source tree is never modified.** | Inputs opened `O_RDONLY`; the source process never creates, writes or unlinks inside the tree. | `test_replicate`: full tree digest + mtimes unchanged after a job. |
| **S14** | **Compression never expands, and decompression never overflows.** | Raw fallback when the compressed block is not smaller; the decoder validates literal length, match offset (≥1, ≤ produced) and match length against the output bound before every copy. | `test_compress`: round-trip fuzz; ratio ≥ 1.0 asserted on incompressible input; **decompressor fuzz on mutated blocks under ASan** — every case a clean error. |
| **S15** | **Randomized and fault tests are reproducible.** | Every random source is seeded and the seed printed; injection points are named IDs, not timings; no wall-clock in test logic. | `faultrunner --case <id> --seed <n>` replays any failure exactly. |
| **S16** | **Two processes never write the same target store.** | `flock` on `<store>/LOCK` held for the process lifetime; a second opener fails cleanly. **And**, because T0 measured a filesystem where `flock` silently does not exclude (§2.5, `CHALLENGES.md` B2), `probe_flock_exclusion()` runs at store-open time and the store **refuses to open** where exclusion cannot be enforced — turning a silent corruption into a startup error that names its own cause. | `test_store`: second open returns an error rather than corrupting; `test_harness` asserts the probe reports correctly on a working filesystem and reports (without asserting) on the bind mount. |
| **S17** | **The target never trusts the source.** A chunk is stored under a fingerprint only if its bytes actually hash to it. | SHA-256 recomputed on every received chunk before it is stored or indexed; mismatch → `ERROR` frame, connection torn down, nothing written. | `test_evil_source`: a source deliberately mislabels a chunk; the target must reject it and the store must still verify clean. |

**Ritual:** at the end of every task in §7, walk this table and answer *"did this task touch S-n, and
what test now covers it?"* Any "not covered" becomes an entry in `CHALLENGES.md` or a new test.

---

## 6. Testing strategy

| Layer | What it catches | Where |
|---|---|---|
| **Unit** | SHA-256 vs NIST vectors; CRC32C vs known values; chunker Min/Max; frame codec round-trip; varint/RLE edges; LZ round-trip; queue single-threaded invariants. | `tests/test_sha256.cpp`, `test_crc32c.cpp`, `test_chunker.cpp`, `test_frame.cpp`, `test_compress.cpp`, `test_queues.cpp` |
| **Property / randomized** | Tree round-trip fidelity across sizes and content classes; CDC boundary-shift preservation; "unchanged tree ⇒ ~0 payload bytes"; "1-byte edit ⇒ ~1 chunk". | `test_replicate.cpp`, `test_negotiate.cpp` |
| **Differential** | Both nodes' canonical chunk lists computed independently must be identical; our chunker vs a deliberately naïve reference implementation. | `test_chunker.cpp`, `test_negotiate.cpp` |
| **Adversarial / fuzz** | Hostile frames, hostile manifests, mutated compressed blocks, mislabelled chunks. | `test_frame_fuzz.cpp`, `test_manifest_hostile.cpp`, `test_compress.cpp`, `test_evil_source.cpp` |
| **Fault injection** | Link drops at every protocol phase; I/O errors at every sync boundary. | `test_faults.cpp` + `include/wanrep/fault.h` |
| **Crash / recovery** | Torn container tails, uncommitted manifests, interrupted commits, stale sessions. | `tools/faultrunner` + `test_recovery.cpp` |
| **Concurrency** | Races, deadlocks, queue item-conservation under N×M load. | `test_queues.cpp`, `test_concurrent.cpp` (also built under TSan) |
| **Sanitizers** | UB, leaks, races. | `scripts/check.sh` builds three configurations: normal, ASan+UBSan, TSan — all suites run in each. |
| **Benchmarks** | The headline numbers. | `bench/*`, recorded in `docs/BENCHMARKS.md` with the exact command that produced them. |

**Rule:** every task in §7 ends with `ctest` green in all three configurations, and no task is "done"
while a suite is red.

---

## 7. Task breakdown — the build order

Each task is a stop point: build green, tests green, then an explanation before moving on.

| # | Task | Deliverable | Gates |
|---|---|---|---|
| **T0** | Foundations | Repo, Dockerfile, `scripts/dev.sh`, `scripts/check.sh`, CMake + CTest, test harness, **measured platform + socket facts**, this spec, `CHALLENGES.md` | Suite green **inside the container** in all 3 configurations; §2.5 filled with measured values |
| **T1** | Content primitives | `sha256.h`, `crc32c.h` (carried from project #1), `chunker.h` (FastCDC/Gear, written here) | NIST vectors; scalar == hardware; Min/Max respected; boundary-shift ≥90%; differential vs reference; size distribution reported |
| **T2** | Wire protocol | `frame.h` (header codec, CRC-before-use), varint, RLE need-set, `FrameReader`/`FrameWriter` | Round-trip codec tests; `test_frame_fuzz` clean under ASan; S7 covered |
| **T3** | Compression | `lz.h` — LZ77-family compressor + **bounds-safe** decompressor | Round-trip fuzz; never-expands asserted; decompressor fuzz on mutated blocks clean under ASan; ratio + MB/s reported (S14) |
| **T4** | Lock-free queues | `spsc_ring.h`, `mpmc_queue.h` | Item-conservation stress under TSan; `bench/queues` vs mutex baseline recorded (S9, R2.2) |
| **T5** | Link layer | `link.h`, `TcpLink`, `WanLink`, `FaultLink`, injection registry | Real TCP round-trip; emulated RTT within tolerance of the request; named drops fire deterministically |
| **T6** | Target store | Chunk containers, sharded index, manifest store, `GENERATIONS` journal, recovery, `flock` | Torn-tail recovery; index rebuild; uncommitted manifest invisible; S2/S3/S16 covered |
| **T7** | Manifest & negotiation | Tree scanner, manifest encode/decode, canonical chunk list, `NEED` computation | Unchanged tree ⇒ ~0 payload; 1-byte edit ⇒ ~1 chunk; hostile-manifest suite (S12) |
| **T8** | End-to-end replication | Source pipeline through the queues, target server, commit protocol, CLI | Tree round-trip byte-exact; TSan clean; `verify --deep` green; S1/S13/S17 |
| **T9** | Resumable transfers | Session journal, checkpoints, resume handshake, bounded re-send | Drop-and-resume at randomized offsets; the "delete the session file" case; re-send bound asserted (S5, S6) |
| **T10** | Fault injection matrix | `tools/faultrunner`, link drops **and** node kills at every named point, the single oracle | Every point × N iterations green; matrix reported in `BENCHMARKS.md` (R3) |
| **T11** | Benchmarks & reconciliation | `bench/*`, `docs/BENCHMARKS.md`, S-table sweep, headline claim reconciliation | Bandwidth reduction + breakdown; RTT curve; queue benchmark; every S1–S17 row has a named passing test; claims rewritten if the numbers say so |

---

## 8. Holes in this spec (found by attacking it on purpose)

### 8.1 "About 60% bandwidth reduction" is meaningless without the workload *and* the baseline

Two different numbers can both honestly be called "bandwidth reduction versus full transfers," and
they differ by an order of magnitude:

- **Initial seed** (target empty): no history to exploit, so savings come only from in-transit
  compression and dedup *within* the tree. Plausibly 40–70% on mixed data, ~0% on incompressible.
- **Incremental generation** (target holds G−1): savings come mostly from not sending unchanged
  data. Plausibly 95–99%.

Quoting the second number and letting a reader assume the first is the standard way replication
benchmarks lie. **Therefore:** `bench/wire_bytes` reports a table — seed, each incremental
generation, and the whole 8-generation campaign versus 8 full transfers — with a per-row breakdown
of bytes avoided by unchanged-file skip, by chunk dedup, by compression, and bytes *spent* on
protocol and manifests. The ≈60% bandwidth claim will be anchored to **one named row**, and the row is
printed next to the number every time. The controls are also reported: unique incompressible data
(expect ≈0%, possibly slightly negative from protocol overhead) and a single 1-byte edit (expect
≈100%). If the anchored row does not land near 60%, the claim changes to whatever is true.

The workload itself is the same model as project #1 so the two are comparable: ~2 000 files, mixed
text/structured-binary/incompressible, captured as 8 successive generations, with ~3% of files
modified, ~1% created and ~1% deleted between generations.

### 8.2 A tree that changes while it is being scanned yields a torn generation

We read files one at a time with no snapshot underneath. If the source tree is live, generation G
can contain file A from before an edit and file B from after it. Every real replication product
solves this with a filesystem/volume snapshot (ZFS, LVM, VSS). We do not, and §3.1's C2 is worded
to say exactly what we can prove ("as it was when the source scanned it") rather than implying
atomicity we do not have. Tests replicate quiescent trees; the limitation is named, not hidden.

### 8.3 On a nearly-unchanged tree, the manifest is the dominant cost

The manifest is ~36 bytes per chunk of the *whole* tree, sent every generation regardless of how
little changed. For a 10 GiB tree at 8 KiB chunks that is ~45 MiB per generation — and if only 1 MiB
of file data actually changed, the manifest is 97% of the transfer. Real systems avoid this by
sending manifest *deltas* keyed on the previous generation, or by keeping the chunk list target-side
and shipping only file-level changes. We send the full manifest because it makes a target
recoverable from any state with no delta chain (§3.1), and that trade is deliberate — but it means
the bandwidth number is dominated by manifest overhead at high similarity, and `bench/wire_bytes`
therefore reports manifest bytes as their own line rather than burying them.

### 8.4 Chunk granularity is a floor on the delta

A one-byte edit costs a whole chunk (~8 KiB), because chunks are the unit of transfer. rsync's
rolling-checksum delta would send a few hundred bytes instead. We are strictly worse on that case
and strictly better on moved/renamed/duplicated data, which chunk-level content addressing gets for
free and rsync's per-file model does not. Naming the trade rather than claiming a win on both sides.

### 8.5 Lock-free may not beat a mutex at these producer counts

An uncontended `std::mutex` on Linux is a couple of atomic operations and never enters the kernel.
With 4–8 producers and items that each represent kilobytes of hashing and compression work, queue
contention may simply not be the bottleneck, and the lock-free queues may measure *the same* as the
mutex baseline. T1's measurement makes this more likely, not less: at 966 MB/s of chunk+hash per
thread, a queue item represents ~8.5 µs of upstream work, which is thousands of times the cost of a
mutex acquisition. The queues will be measured against that baseline in T4 with the expectation
that the honest answer may be "no faster, and kept for the bounded-latency property." If that is what `bench/queues` says, it goes in `BENCHMARKS.md` as the result, the
queues stay (for the bounded-latency and no-blocking-under-backpressure properties, which are real
and separately measurable), and the headline claim is reworded from a performance claim to a design
claim. The measurement decides the wording; the wording does not decide the measurement.

### 8.6 `fsync` inside Docker on macOS is not a power-loss durability guarantee

The container's writes land in a VM (virtiofs) on top of APFS. We can honestly test
**process-crash consistency** (`kill -9` → reopen → verify), and we do, extensively. We cannot
honestly test **power-loss durability** on this hardware. The distinction is stated in the README
rather than quietly blurred, because "we fsync in the right order" and "we survive power loss" are
different claims and only one of them is testable here.

### 8.7 No transport security — stated, not implied

There is no TLS and no authentication (§1). The threat model is therefore: *the link may corrupt
or truncate data, and a peer may be buggy or malicious in what it sends* — both of which we defend
against (S7, S12, S17) — but *the link is not confidential and the peer is not authenticated*. An
attacker on the path can read the data, and anyone who can connect can push a generation. Written
down so it is a scoping decision rather than an oversight, and so the S17 "never trust the sender"
work is understood as protecting *integrity*, which it does, and not *authenticity*, which it
cannot.

### 8.8 The emulated WAN is not a WAN

`WanLink` adds latency and a bandwidth ceiling on top of loopback TCP. It does not reproduce
congestion-control dynamics, competing traffic, bufferbloat, MTU discovery, or the tail behaviour of
a real path. It is a *reproducible* model chosen so the fault matrix is deterministic, and every
number produced under it is labelled as emulated. `tc netem` in the container gives a real-kernel
cross-check of the latency path; nothing available here cross-checks the rest.

### 8.10 The container has two filesystems, and they do not agree

`/tmp` is container-local overlayfs; `/work` is the bind-mounted macOS directory over
virtiofs. `rename` and every flavour of `fsync` behave identically on both — but
`flock` exclusion **works on the first and silently does not on the second** (§2.5).
The consequences are scoped deliberately:

- **Test and benchmark stores live on container-local storage**, never on `/work`. A
  store on the bind mount would also make every I/O measurement a measurement of
  virtiofs rather than of this code.
- **The product refuses to run where its own safety mechanism does not work**, via the
  open-time probe in S16, rather than trusting a filesystem it did not choose.
- **§8.6's caveat is now two caveats.** We already could not test power-loss durability
  here. We additionally cannot test multi-process store exclusion on the bind mount,
  because there is nothing there to test — the primitive is absent, not weak.

The general lesson, recorded because it is the kind of thing that is obvious only
afterwards: a POSIX call succeeding is not evidence that it did anything. `flock`
returned 0 both times.

### 8.9 Chunk-size distribution is a property of the content, and T1 measured how much

Every per-chunk overhead figure above (36 B manifest entry, 48 B record header, ~0.44%) assumes the
chunker actually produces ~8 KiB average chunks. **On random data it does** — T1 measured mean
9 316 B, p1 2 303, p50 9 198, p99 17 048, max 26 436, with 0.000% of chunks hitting the 64 KiB
ceiling.

**On constant-byte runs it does not, and cannot.** T1 derived and confirmed that the Gear hash
*freezes* at `-gear[b]` after 64 bytes of identical input, so no constant run of any of the 256 byte
values can ever be cut by content (`CHALLENGES.md` B3). Sparse files and zero-padded images chunk at
exactly `MaxSize`, 8× the assumed average.

That is benign for bandwidth — the forced chunks are byte-identical, so they share one fingerprint
and cost one payload — but it means **the per-chunk overhead arithmetic must be quoted per content
class, never as a single number for the corpus.** `bench/wire_bytes` reports manifest bytes as their
own line (§8.3) for exactly this reason.
