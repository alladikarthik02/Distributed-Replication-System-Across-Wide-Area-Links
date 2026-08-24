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

Pending: T3 compression ratio and MB/s · T4 queue throughput vs mutex baseline ·
T11 bandwidth reduction, RTT curve, resume cost.
