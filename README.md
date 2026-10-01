# wanrep — Distributed Replication System Across Wide-Area Links

One-way, generational replication of a directory tree between two machines over a slow,
high-latency link. Written from scratch in **C++20** with **no external dependencies** —
chunker, SHA-256, CRC32C, compressor, lock-free queues, wire protocol, and on-disk store
are all in this repository.

The design goal is narrow and testable: **send only what changed, and never leave the
receiving side holding half a backup.**

```
source (A)                                                   target (B)
──────────                                                   ──────────
scan tree, cut files into content-defined chunks,
name each chunk by the SHA-256 of its own bytes,
write a manifest

   ──────── manifest ────────────────────────────────────►    derive the same chunk
                                                              numbering, then ask its
                                                              OWN store what it lacks
   ◄─────── NEED {3, 7-9} (run-length encoded) ──────────

read those chunks, batch them,
compress the batch, frame it
   ──────── CHUNKS (streamed, no per-chunk acks) ───────►      re-hash every chunk on
                                                              arrival, append to store
   ──────── GEN_COMMIT ─────────────────────────────────►      fsync chunks → write
                                                              manifest → append ONE
                                                              commit record → fsync
   ◄─────── COMMIT_ACK ──────────────────────────────────
```

Three to five round trips per generation, **independent of dataset size**.

## Why it is built this way

| Decision | Reason |
|---|---|
| **Every chunk is named by the SHA-256 of its own bytes** | "What changed?" becomes a set difference the target answers from its own storage — no timestamps, no history from the source, no trust. A renamed or moved file transfers nothing. Re-sending a chunk is a no-op, which is what makes retries and resume safe by construction. |
| **Content-defined chunk boundaries** (Gear rolling hash, FastCDC normalization) | Fixed-size chunking collapses on insertion: one added byte shifts every later boundary and changes every fingerprint. Measured: **100.00%** of boundaries preserved after a 1-byte insert, against **0.20%** for a fixed-size control. |
| **One batched negotiation, then streaming with no per-chunk acks** | On a long link the enemy is round trips, not bytes. Chunk-at-a-time request/response caps throughput at one chunk per RTT — under 1% of a 100 Mbit/s link at 100 ms RTT, and invisible on a laptop. |
| **The frame header carries its own CRC, checked before any other field** | The header holds the payload length, which decides an allocation. The payload CRC can only be verified *after* reading, i.e. after that allocation. A test sends a frame claiming a 3 GiB payload **with a valid header CRC**, so only the fixed 1 MiB bound can refuse it. |
| **Compression never expands** | Incompressible input (encrypted, already compressed) grows under any compressor. If the compressed batch is not smaller, the raw bytes go on the wire with the flag cleared. Control measurement on unique incompressible data: **−0.41%**, the honest cost of protocol overhead. |
| **A generation exists if and only if its commit record is durable** | Chunks and the manifest are written and fsynced first and mean nothing while no record names them. One small append, fsynced, is the atomic instant. Every crash window leaves either the previous state plus harmless unreferenced chunks, or the complete new generation. |
| **Recovery resynchronizes instead of guessing** | A record that fails to parse is either a torn tail (crash mid-append) or mid-file damage (bit rot) — identical from where the scanner stands. It scans forward for the next fully valid record: found means mid-file damage, so skip that span, keep the rest, and report it. |
| **Resume re-negotiates; it does not remember a position** | The earlier design tracked a contiguous high-water mark. Batches are compressed on several threads and arrive out of order, so one missing early batch pinned the mark near zero and "resume" re-sent chunks the target already held — it measured **slower than the fallback it was optimizing**. The store is the authority. |
| **Bounded lock-free queues on the pipeline hot path** | Uncontended push/pop take no lock, so a descheduled thread cannot block its peers. Bounding them is what keeps memory constant regardless of tree size; the full-queue path yields and is **not** claimed to be lock-free. Measured honestly: **0.97× throughput** against a mutex baseline under realistic per-item cost, **6.5× better p99 push latency**. |

## Measured results

Every figure below is read from the transport's own byte counter (`Link::bytes_out()`),
including all protocol overhead — never modelled from chunk sizes. Bandwidth reduction is
a property of the data as much as the code, so the benchmark prints its workload above
every number and reports three separate figures instead of one flattering one.

| | measured |
|---|---|
| Bandwidth, initial sync to an empty target | **52.8% reduction** |
| Bandwidth, incremental generations | **98.9% reduction** |
| Bandwidth, whole 8-generation campaign | **93.0% reduction** |
| Attribution on the initial sync | **compression does nearly all of it** (52.3% with compression, −0.5% without); dedup earns its keep on later generations |
| Cost of a mid-transfer link drop | **+8.7%** over a clean run; a restart would be +100% |
| With the session file deleted entirely | still **38%** of a full transfer — the target skips what it holds because it *looks*, not because it remembers |
| Round trips per generation | **3–5, independent of dataset size** |
| Chunking + SHA-256, single thread | **966 MB/s** — 77× what a 100 Mbit/s link can consume |
| Boundary preservation after a 1-byte insert | **100.00%** vs **0.20%** for a fixed-size control |
| Fault injection | 8 named in-process link-drop/IO points, 12/12 process-kill cases pass with every child confirmed `killed`, 40 garbage payloads rejected |
| Test suites | 14, green under `-O2`, ASan+UBSan, and TSan; 25 consecutive runs, 0 flakes |

Full tables, each with the exact command that produced them, in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## Build and test

Everything builds and runs **inside Linux in Docker**. The claims here are about OS
behaviour — short writes on sockets, `SIGPIPE` on a dead peer, the difference between an
orderly close and an abortive one, `fsync` ordering, `flock` — and macOS and Linux
disagree on several of them.

```bash
git clone https://github.com/alladikarthik02/Distributed-Replication-System-Across-Wide-Area-Links.git
cd Distributed-Replication-System-Across-Wide-Area-Links
./scripts/dev.sh ./scripts/check.sh
```

That runs the full suite three times: normal `-O2`, ASan+UBSan (memory safety), and TSan
(races and lock-order inversions). ASan and TSan cannot share a binary, which is why it is
three build trees. For a single configuration:

```bash
./scripts/dev.sh ./scripts/check.sh none
```

Randomized tests are seeded and print their seed; replay a failure with
`WANREP_SEED=0x... ./build-none/test_harness`.

## Try it

```bash
# terminal 1 — a target, on container-local storage (see the caveat below)
./scripts/dev.sh ./build-none/wanrep target serve --store /tmp/store --listen 127.0.0.1:9000

# terminal 2 — replicate a tree, verify the store, rebuild the tree from it
./scripts/dev.sh ./build-none/wanrep source replicate --tree ./docs --peer 127.0.0.1:9000 --dataset docs
./scripts/dev.sh ./build-none/wanrep target verify --store /tmp/store --deep
./scripts/dev.sh ./build-none/wanrep target materialize --store /tmp/store --dataset docs --gen 0 --out /tmp/out
```

Add `--rtt 100 --bw 12.5` to `source replicate` to put the transfer behind the WAN
emulator (fixed round-trip delay plus a token-bucket bandwidth ceiling) and watch the
round-trip count, not the byte count, decide the wall clock.

```
wanrep target serve       --store <dir> --listen <host:port> [--once]
wanrep target ls          --store <dir> [--dataset <name>]
wanrep target materialize --store <dir> --dataset <name> --gen <n> --out <dir>
wanrep target verify      --store <dir> [--deep]
wanrep source replicate   --tree <dir> --peer <host:port> --dataset <name>
                          [--gen <n>] [--rtt <ms>] [--bw <MB/s>]
```

## Repository layout

```
include/wanrep/     the implementation, header-only
  chunker.h           Gear rolling hash + FastCDC normalized chunking
  sha256.h            chunk identity (runtime dispatch to ARMv8 SHA-2 where available)
  crc32c.h            cheap corruption detection, on the wire and on disk
  lz.h                LZ77-family compressor + bounds-safe decoder
  frame.h             wire framing; header CRC verified before any field is used
  manifest.h          the per-generation tree description and canonical chunk numbering
  negotiate.h         the set difference — the file that makes "only changed chunks" true
  chunk_store.h       append-only chunk containers, sharded index, damage-reporting recovery
  generation_store.h  the GENERATIONS journal; commit is one record plus one fsync
  target_store.h      store lifecycle, the flock/fsync capability probe, verify() oracle
  protocol.h          target state machine and the source's three-stage pipeline
  spsc_ring.h         single-producer/consumer ring
  mpmc_queue.h        bounded MPMC queue (Vyukov), used by the pipeline
  link.h tcp_link.h   transport abstraction and TCP
  wan_link.h          latency + bandwidth emulation
  fault.h fault_link.h  named fault-injection points
tests/              14 suites, including adversarial and fuzz cases
bench/              chunker, hash, compressor, queues, wire-bytes benchmarks
tools/faultrunner   forks a real target process and SIGKILLs it mid-write
scratch/            the two spikes that settled platform questions (see the bug journal)
docs/               spec, bug journal, measurements
```

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — architecture, the consistency contract, the wire
  protocol, safety requirements S1–S17 with the test that proves each, the task ladder,
  and a section on where the design is weak.
- [`docs/CHALLENGES.md`](docs/CHALLENGES.md) — a bug journal: every bug hit while building
  this, in symptom → hypotheses (including the wrong ones) → isolation → root cause →
  fix → what it generalizes to form. Three worth reading on their own:
  - **B4** — recovery was deleting good data. One flipped byte in the first of five chunk
    records destroyed all five, and `verify()` reported the store clean, because nothing
    was left to be wrong about.
  - **B7** — the fast resume path was slower than the fallback it was optimizing, and the
    tell was a correct fix that moved the number by one percent.
  - **B8** — two fault-injection cases passed without injecting anything. Caught only
    because the runner prints *how* each child process died.
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — every number with its command and its
  workload, including the controls that are designed to fail and the attribution row that
  shows compression, not dedup, carrying the initial sync.

## What this deliberately does not do

- **No two-way sync.** Replication is one-way, source to target. No conflict resolution,
  no vector clocks, no consensus.
- **No security.** No encryption, no authentication. CRCs catch accidents; the defences
  against a hostile peer are the size bounds, the bounds-checked decoder, and SHA-256
  re-verification of every chunk on arrival.
- **No garbage collection.** Chunks no generation references any more are never reclaimed.
- **No source-side snapshot.** A file modified while the source is reading it can be
  captured as a mix of old and new.
- **Chunk-granular dedup only.** No byte-granular delta inside a chunk.
- **The chunk index is RAM-resident** and has not been measured at a scale where that
  matters.

### Two things this environment cannot honestly prove

1. **Power-loss durability.** Writes land in a VM on top of APFS. Process-crash
   consistency (`kill -9` → reopen → verify) is tested extensively; that is a different
   claim. See [`docs/SPEC.md`](docs/SPEC.md) §8.6.
2. **Store exclusion on a bind mount.** `flock` silently fails to exclude on the virtiofs
   share ([`docs/CHALLENGES.md`](docs/CHALLENGES.md) B2) — two processes both acquire the
   "exclusive" lock, with no error. The store probes for this when it opens and refuses to
   run where its own safety mechanism does not work, so keep stores on container-local
   storage.

## Build status

| Task | What | State |
|---|---|---|
| T0 | Foundations: container, CMake+CTest, harness, measured platform and socket facts, spec, bug journal | done |
| T1 | Content primitives: SHA-256, CRC32C, FastCDC chunker | done |
| T2 | Wire protocol: frame codec, CRC-before-use, varint, run-length-encoded need set | done |
| T3 | In-transit compression: LZ77-family compressor + bounds-safe decoder | done |
| T4 | Lock-free queues: SPSC ring + bounded MPMC, against a mutex baseline | done |
| T5 | Link layer: TCP, WAN emulator, fault injection | done |
| T6 | Target store: chunk containers, index, manifests, generation journal | done |
| T7 | Manifest and negotiation: the set difference | done |
| T8 | End-to-end replication + CLI | done |
| T9 | Resumable transfers | done |
| T10 | Fault-injection matrix: link drops and node kills | done |
| T11 | Benchmarks and reconciliation | done |

## License

BSD 3-Clause. See [`LICENSE`](LICENSE).
