# `wanrep` — measurements

Every number here is reproducible by a stranger running one command in the container.
A number without the command that produced it does not go in this file, and an
optimization without a before/after does not go in the code.

**Rule for this project specifically:** every bandwidth figure is read from
`Link::bytes_out()` — the actual byte counter on the socket, including all protocol
overhead — never modelled or estimated from chunk sizes.

## T0 — environment baseline

Command:

```bash
./scripts/dev.sh ./build-none/test_harness
```

| Measurement | Value | Notes |
|---|---|---|
| Platform | Ubuntu 24.04, GCC 13, linux/aarch64, 8 CPUs | Docker on Apple silicon |
| L1 cache line | 64 bytes | sizes the SPSC ring's padding |
| One `send()` of 4 MiB (4 KiB socket buffers) | **6 144 bytes moved** | short writes are the normal case, not the exception |
| Loopback RTT | p50 **2.6–10.2 µs**, p99 up to **54 µs** | 25 runs × 500 samples; the floor under the WAN emulator |
| `steady_clock` granularity | ≈ **41 ns** | every latency number below comes from this clock |
| Suite determinism | **25/25 green**, 0 flakes | checked before building anything on top |

## T1 — content primitives

Commands:

```bash
./scripts/dev.sh ./build-none/bench_hash
./scripts/dev.sh ./build-none/bench_chunker
./scripts/dev.sh ./build-none/test_chunker
```

### Throughput (64–256 MiB buffers, aarch64)

| Primitive | Throughput | Note |
|---|---|---|
| SHA-256, scalar | 122.5 MB/s | the portable path |
| SHA-256, ARMv8 SHA-2 | **1 960.8 MB/s** | 16.0× — chosen at runtime from `AT_HWCAP` |
| CRC32C, table | 2 025.3 MB/s | |
| CRC32C, ARMv8 CRC32 | **7 838.0 MB/s** | 3.9× — makes per-frame integrity checking free |
| CRC32C, bitwise oracle | 91.4 MB/s | reference implementation, used only to verify the other two |
| Chunking alone (Gear/FastCDC) | **1 854.8 MB/s** | 28 745 chunks over 256 MiB, mean 9 339 B |
| **Chunking + SHA-256** | **966.1 MB/s** | the real per-byte source cost, single-threaded |

**What the last row means for the design.** 966 MB/s on one thread against a 100 Mbit/s
WAN link (12.5 MB/s) is **77× headroom**; a 1 Gbit/s link needs 13% of one core. The
source pipeline's fan-out (SPEC §3.6) therefore is *not* what makes the WAN case work —
one thread already does. It earns its place for LAN/loopback-speed runs and for the
compressor stage. Recorded here so the concurrency claims in T4 are made next to the
number that says what a single thread could already do.

### Chunk-size distribution — random data, 32 MiB

| mean | p1 | p50 | p99 | max | forced at 64 KiB |
|---|---|---|---|---|---|
| 9 316 B | 2 303 B | 9 198 B | 17 048 B | 26 436 B | **0.000%** |

Target average is 8 KiB; normalized chunking (NC=2) lands the median at 9 198 B with no
chunk anywhere near the ceiling. SPEC §8.9's per-chunk overhead arithmetic is valid for
this content class.

### Chunk-size distribution — constant-byte runs

| content | chunks per MiB | forced at 64 KiB | distinct fingerprints |
|---|---|---|---|
| 1 MiB of `0x00` / `0xff` / `'A'` | 16 | **100%** | 1 |

The Gear hash freezes after 64 bytes of identical input, so no constant run of any of the
256 byte values can ever be cut by content (`CHALLENGES.md` B3). Benign: the forced chunks
are byte-identical and collapse to one stored chunk. It does mean the "≈8 KiB average"
figure is off by 8× on sparse data, which is why §8.9 requires the distribution to be
quoted per content class.

### The property the project rests on (SPEC R1.1)

One byte inserted at offset 1000 of a 4 MiB file:

| chunker | downstream boundaries preserved |
|---|---|
| **Content-defined (FastCDC/Gear)** | **100.00%** |
| Fixed-size 8 KiB (control) | 0.20% |

Both numbers are exact rather than statistical, and both were derived before being
believed. CDC re-synchronises *precisely*: 64 bytes past the edit the two hash streams
are the same sequence offset by one, so every downstream cut lands at `original + 1`. The
control's 0.20% is 1/512 — the end-of-file boundary, the only one that maps back onto
itself. A separate in-place (non-shifting) edit changed **1 chunk out of 444**.

---

## T11 — the headline numbers

### Bandwidth reduction (R1.5) — the headline

```bash
./scripts/dev.sh ./build-none/bench_wire --files 300 --generations 8
```

**The workload, which is printed with every run because the number is meaningless without
it (SPEC §8.1):** 300 files at generation 0 — 45% prose, 35% fixed-width records, 20%
incompressible — captured as 8 successive generations, with ~3% of files modified
(in-place edit / append / truncate), ~1% created and ~1% deleted between generations.
Seed `0x9e3779b97f4a7c15`. Every byte figure is read from `Link::bytes_out()`, the
transport's own counter, so it includes all protocol overhead.

| gen | logical | wire | reduction | manifest | payload | chunks sent | skipped |
|---|---|---|---|---|---|---|---|
| 0 | 18,407,873 | 8,681,330 | **52.84%** | 92,617 | 8,586,296 | 2,102 | 0 |
| 1 | 18,304,861 | 222,743 | 98.78% | 92,239 | 130,231 | 29 | 2,062 |
| 2 | 18,088,527 | 162,348 | 99.10% | 91,491 | 70,584 | 20 | 2,049 |
| 3 | 18,068,898 | 179,440 | 99.01% | 91,597 | 87,570 | 31 | 2,041 |
| 4 | 18,027,708 | 222,738 | 98.76% | 91,497 | 130,968 | 28 | 2,041 |
| 5 | 17,926,126 | 205,476 | 98.85% | 91,330 | 113,873 | 30 | 2,034 |
| 6 | 17,716,735 | 219,022 | 98.76% | 90,782 | 127,935 | 39 | 2,009 |
| 7 | 17,491,122 | 164,298 | 99.06% | 90,004 | 74,021 | 17 | 2,008 |

**Three headline rows. Quote one WITH its label — never a bare number:**

| | what it measures | reduction |
|---|---|---|
| **A. Initial seed** | target empty; the saving is compression + intra-tree dedup | **52.8%** |
| **B. Incremental gens 1–7** | target holds the previous generation | **98.9%** |
| **C. Whole 8-gen campaign** | all 8 generations vs 8 full transfers | **93.0%** |

**Controls, which bound the claim on both sides:**

| control | expected | measured |
|---|---|---|
| unique incompressible data | ≈0% | **−0.41%** (protocol overhead; the payload itself never expands, S14) |
| single 1-byte edit in 4 MB | ≈100% | **98.93%** — 2 chunks |

**Attribution — where the seed-sync saving actually comes from:**

| | seed transfer | reduction |
|---|---|---|
| compression on | 12,614,165 → 6,017,153 | **52.3%** |
| compression off | 12,614,165 → 12,680,699 | **−0.5%** |

Worth being blunt about: on this corpus **essentially all of row A is compression**, not
deduplication. The files are generated independently, so there is almost no cross-file
redundancy for chunk dedup to find on a first sync. Dedup earns its keep in rows B and C,
where it is doing all the work instead. A benchmark that reported only row A would credit
the wrong mechanism, which is why the attribution row exists.

### Round trips vs RTT (R1.6)

| emulated RTT | elapsed | throughput | round trips | per GiB |
|---|---|---|---|---|
| 0 ms (loopback, **not** a 0 ms WAN) | 0.034 s | 32.66 MB/s | 3 | 1,074 |
| 10 ms | 0.072 s | 15.35 MB/s | 3 | 1,074 |
| 50 ms | 0.206 s | 5.37 MB/s | 3 | 1,074 |
| 100 ms | 0.348 s | 3.18 MB/s | 3 | 1,074 |

Round trips are **constant per generation, independent of dataset size** — which is the
number that predicts behaviour at an RTT we did not test (SPEC §3.2). A stop-and-wait
design would have shown one round trip per chunk and collapsed here.


### Lock-free queues vs a mutex baseline (R2.2) — the honest answer

```bash
./scripts/dev.sh ./build-none/bench_queues
```

SPEC §8.5 committed in advance to reporting whatever this said, including "no faster".
It says no faster, and the *shape* of the result is the interesting part:

| measurement | lock-free vs `std::mutex` + condvar |
|---|---|
| **Table 1** — synthetic: producers do nothing but push | **2.1× throughput** (geomean, range 1.2–3.7×) |
| **Table 3** — realistic: T1's measured ~8.5 µs of chunk+SHA-256 per item | **0.97× throughput** (geomean, range 0.84–1.01×) |
| **Table 3** — p99 push latency | **6.5× better** (geomean, best 29.7×) |
| Slowest configuration measured anywhere | 108,411 items/s = **71×** what a 100 Mbit/s link can consume |

Table 1 is the number it would be tempting to quote, and it would be false of this system:
it gives the producer nothing to do but push, so the queue is 100% of the work and
contention sits at its theoretical maximum. Restore the real upstream cost and the
throughput advantage **drains away** — the signature of both queues being pinned by CPU
cost rather than by the queue. The tail advantage survives.

**So the second headline claim should be a design claim, not a performance claim.** On
this workload the lock-free queues buy no throughput the link could ever use; what they
buy is a bounded tail, no producer blocked by a descheduled peer, and memory bounded by
construction. Quoting the 2.1× as a pipeline speedup would be true of the benchmark and
false of the system.

### Resume cost (R2.4)

```bash
./scripts/dev.sh ./build-none/test_resume
```

| scenario | before the B7 fix | after |
|---|---|---|
| drop mid-transfer, then resume | +53.1% over a clean run | **+8.7%** |
| `run_resilient` through 3 drops | 2.06× | **1.37×** |
| session file deleted entirely, fresh negotiation | 56% of a full transfer | **38%** |

A true restart would cost 100% extra. The last row is the important one: even with every
trace of the session deleted, the target still skipped 203 of 332 chunks — because resume
is a property of content addressing, not of bookkeeping (SPEC §3.0).

### Fault matrix (R3)

```bash
./scripts/dev.sh ./build-none/faultrunner --iterations 2
./scripts/dev.sh ./build-none/test_faults
```

| | cases | result |
|---|---|---|
| Named link-drop / IO-error points, in-process | 8 | all survive, all verified by one oracle |
| Process kills (`SIGKILL` from outside, `_exit(137)` from inside) | 12 (2 iterations × 6) | **12/12 pass**, every child confirmed `killed` |
| Garbage payloads to the target | 40 | rejected, store clean every time |
| Frame claiming a 3 GiB payload with a **valid** header CRC | 1 | refused by the length bound alone (S7) |

The kill cases include the sharpest one — the target killed with the manifest durable and
the COMMIT record not yet written. Recovery leaves the generation invisible and the retry
completes it.

---

## Claim reconciliation

SPEC §2's integrity rule: *if the finished system cannot hit a number it states, we
change the claim, not the measurement.* One claim needs changing.

> **As written:** "...sending only changed chunks and compressing them in transit to
> reduce bandwidth use by about 60% versus full transfers."

**Measured:** 52.8% on an initial seed, 98.9% on incremental generations, 93.0% across the
campaign. "About 60%" matches none of them — it understates two and overstates the third.

**Suggested rewrite, using numbers this repository can reproduce:**

> "...sending only changed chunks and compressing them in transit, cutting wire bytes by
> 53% on an initial full sync and by 99% on subsequent generations of a slowly-changing
> backup corpus — 93% across an 8-generation campaign, measured on the socket rather than
> estimated."

> **Bullet 2, as written:** "Handled concurrency with careful locking and lock-free queues
> on the hot path, and added resumable transfers so a replication job recovered cleanly
> from a dropped connection rather than restarting from the beginning."

**This stands** — but only because it is already a *design* claim rather than a throughput
one. Do not add a speed number to it: the measured throughput ratio against a mutex
baseline is 0.97× under realistic per-item cost (the 2.1× is a property of the
microbenchmark, not the pipeline). If a number is wanted, the defensible one is the tail:
**6.5× better p99 push latency**, geomean. The resume half is backed by +8.7% rather than
+100%.

> **Bullet 3, as written:** "Validated consistency and recovery through fault-injection
> tests that dropped links and killed nodes mid-transfer, confirming the target stayed
> correct after every simulated failure."

**This stands as written**, and is the best-evidenced of the three: 8 named in-process
fault points, 12 process-kill cases (`SIGKILL` from outside and `_exit` from inside, every
child confirmed killed rather than exited — see `CHALLENGES.md` B8), 40 garbage payloads,
and a hostile frame with a valid header CRC — all ending in the same oracle.
