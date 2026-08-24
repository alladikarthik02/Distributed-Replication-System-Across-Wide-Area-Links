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

Pending: T1 chunker throughput and size distribution · T3 compression ratio and MB/s ·
T4 queue throughput vs mutex baseline · T11 bandwidth reduction, RTT curve, resume cost.
