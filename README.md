# `wanrep` — Distributed Replication System Across Wide-Area Links (C++20)

One-way, generational replication of a directory tree between two nodes over a
high-latency link. The source splits files into **content-defined chunks**, the two nodes
**negotiate a set difference** so only chunks the target lacks ever cross the wire, those
chunks are **compressed in transit**, and the generation is **committed atomically** on
the target. A dropped link or a killed node **resumes** instead of restarting.

- **Spec:** [`docs/SPEC.md`](docs/SPEC.md) — architecture, essential functions, safety
  requirements (S1–S17), task breakdown.
- **Bug journal:** [`docs/CHALLENGES.md`](docs/CHALLENGES.md) — every bug hit while
  building this, with the reasoning, including the wrong hypotheses.
- **Measurements:** [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — every number, with the
  command that produced it.

## Build and test

Everything builds and runs **inside Linux in Docker**. The claims here are about OS
behaviour — short writes on sockets, `SIGPIPE` on a dead peer, the difference between an
orderly close and an abortive one, `fsync` ordering, `flock` — and macOS and Linux
disagree on several of them.

```bash
./scripts/dev.sh ./scripts/check.sh
```

That runs the full suite three times: normal `-O2`, ASan+UBSan (memory safety, S7/S14),
and TSan (races, S8/S9). For a single configuration:

```bash
./scripts/dev.sh ./scripts/check.sh none
```

Randomized tests are seeded and print the seed; replay a failure with
`WANREP_SEED=0x... ./build-none/test_harness`.

### Two things this environment cannot honestly prove

1. **Power-loss durability.** Writes land in a VM on top of APFS. We test process-crash
   consistency (`kill -9` → reopen → verify) extensively; that is a different claim.
   See [`docs/SPEC.md`](docs/SPEC.md) §8.6.
2. **Store exclusion on the bind mount.** `flock` silently does not exclude on the
   virtiofs share (`docs/CHALLENGES.md` B2). The store probes for this at open time and
   refuses to run where its own safety mechanism does not work. Keep stores on
   container-local storage. See §8.10.

## Status

| Task | What | State |
|---|---|---|
| T0 | Foundations: container, CMake+CTest, harness, **measured platform + socket facts**, spec, bug journal | ✅ done |
| T1 | Content primitives: SHA-256, CRC32C, FastCDC chunker | ✅ done |
| T2 | Wire protocol: frame codec, CRC-before-use, varint, RLE need-set | ✅ done |
| T3 | In-transit compression: LZ77-family compressor + bounds-safe decoder | ✅ done |
| T4 | Lock-free queues: SPSC ring + bounded MPMC, vs a mutex baseline | ✅ done |
| T5 | Link layer: TCP, WAN emulator, fault injection | ✅ done |
| T6 | Target store: chunk containers, index, manifests, generation journal | ✅ done |
| T7 | Manifest & negotiation: the set difference | ✅ done |
| T8 | End-to-end replication + CLI | ✅ done |
| T9 | Resumable transfers | ✅ done |
| T10 | Fault injection matrix: link drops and node kills | ✅ done |
| T11 | Benchmarks — the headline numbers — and reconciliation | ✅ done |

## The numbers

Full detail, with the workload printed beside every figure, in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

| | measured |
|---|---|
| Bandwidth, initial seed sync | **52.8% reduction** |
| Bandwidth, incremental generations | **98.9% reduction** |
| Bandwidth, 8-generation campaign | **93.0% reduction** |
| Cost of a mid-transfer link drop | **+8.7%** over a clean run (a restart would be +100%) |
| Round trips per generation | **3–5, independent of dataset size** |
| Fault matrix | 8 named in-process points + 12 process-kill cases, all verified by one oracle |

Every bandwidth figure is read from `Link::bytes_out()` — the transport's own byte counter,
including all protocol overhead — never modelled from chunk sizes.

## Try it

```bash
# terminal 1: a target, on container-local storage (see the caveat below)
./scripts/dev.sh ./build-none/wanrep target serve --store /tmp/store --listen 127.0.0.1:9000

# terminal 2: replicate a tree, then check and rebuild it
./scripts/dev.sh ./build-none/wanrep source replicate --tree ./docs --peer 127.0.0.1:9000 --dataset docs
./scripts/dev.sh ./build-none/wanrep target verify --store /tmp/store --deep
./scripts/dev.sh ./build-none/wanrep target materialize --store /tmp/store --dataset docs --gen 0 --out /tmp/out
```
