# wanrep

`wanrep` replicates a directory tree from one machine to another across a slow,
high-latency network link. It sends only the parts of the tree that the receiving side does
not already have, compresses them on the way, and applies each run as an all-or-nothing
snapshot, so a crash or a dropped connection can never leave a half-applied copy behind.

It is written in C++20 with no external dependencies. The chunker, SHA-256, CRC32C,
compressor, lock-free queues, wire protocol, and on-disk store are all in this repository.

## Contents

- [What problem it solves](#what-problem-it-solves)
- [Architecture](#architecture)
  - [The pieces](#the-pieces)
  - [A transfer, end to end](#a-transfer-end-to-end)
  - [How a snapshot becomes durable](#how-a-snapshot-becomes-durable)
  - [What happens when something breaks](#what-happens-when-something-breaks)
- [Using it as a library](#using-it-as-a-library)
  - [Adding it to a build](#adding-it-to-a-build)
  - [Replicating a tree](#replicating-a-tree)
  - [Surviving a dropped connection](#surviving-a-dropped-connection)
  - [Running a target](#running-a-target)
  - [Reading, verifying and restoring a store](#reading-verifying-and-restoring-a-store)
  - [Using the chunker on its own](#using-the-chunker-on-its-own)
  - [Testing against a slow link](#testing-against-a-slow-link)
  - [Error handling](#error-handling)
- [Command line](#command-line)
- [Building and running the tests](#building-and-running-the-tests)
- [Measurements](#measurements)
- [Limitations](#limitations)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [License](#license)

## What problem it solves

Say you back up a directory to another city every night. Sending the whole thing each time
is wasteful, and sending only the files whose timestamps changed is not much better: edit
one row in a large database file and you resend the whole file.

So `wanrep` works below file level. It cuts each file into pieces and gives every piece a
name computed from its own bytes, the SHA-256 of its contents. Once pieces are named that
way, "what has changed?" stops being a question about history and becomes a question the
receiver can answer by itself: it reads the list of piece names, checks which ones it
already stores, and asks for the rest. Nothing depends on timestamps, on the sender
remembering what it sent last time, or on the receiver trusting the sender.

Two useful properties fall out of that. A file that was renamed or moved but not edited
transfers nothing, because its pieces still have the same names. And sending a piece twice
is harmless, because the second copy is the same bytes as the first, which is what makes
interrupted transfers safe to retry.

The second half of the problem is the link itself. Over a long-distance connection the
expensive thing is not bandwidth but waiting: ask the receiver about one piece, wait for
the answer, repeat, and throughput collapses to one piece per round trip no matter how
wide the pipe is. `wanrep` therefore does all its asking in a single exchange and then
streams the data without waiting for acknowledgements, which keeps a transfer at three to
five round trips whether the tree is 20 MB or 20 TB.

## Architecture

Replication is one-way: a **source** reads a local tree and a **target** stores it. Each
completed run is a **generation**, numbered 0, 1, 2 and so on. A generation is a complete
description of the tree at the moment it was scanned, not a delta against the previous one,
so the target can be brought up to date from any starting state, including empty.

### The pieces

| Component | Header | Responsibility |
|---|---|---|
| Chunker | [`chunker.h`](include/wanrep/chunker.h) | Decides where one piece of a file ends and the next begins, using a Gear rolling hash with FastCDC normalization. Boundaries follow content, so inserting a byte does not shift every boundary after it. |
| Content hash | [`sha256.h`](include/wanrep/sha256.h) | Names each chunk. Dispatches to ARMv8 SHA-2 instructions at runtime when the CPU has them. |
| Integrity check | [`crc32c.h`](include/wanrep/crc32c.h) | Cheap detection of accidental corruption, on every frame and every on-disk record. Not a substitute for the content hash, and not a security mechanism. |
| Manifest | [`manifest.h`](include/wanrep/manifest.h) | The description of one generation: every file with its metadata, its whole-file digest, and the ordered list of its chunk names. Also derives the canonical chunk numbering both sides use. |
| Negotiation | [`negotiate.h`](include/wanrep/negotiate.h) | The set difference. Given an incoming manifest, asks the local store which chunks are missing and produces the list to request. |
| Compressor | [`lz.h`](include/wanrep/lz.h) | An LZ77-family codec used on batches of chunks. Falls back to raw bytes whenever compression would not shrink the batch. The decoder validates every instruction before executing it, because it runs on bytes that arrived from the network. |
| Framing | [`frame.h`](include/wanrep/frame.h) | Message boundaries over a byte stream. The header carries its own CRC, verified before any other header field is used, because one of those fields decides how much memory to allocate. |
| Chunk store | [`chunk_store.h`](include/wanrep/chunk_store.h) | Append-only chunk containers plus a sharded in-memory index. Recovery scans containers, distinguishes a torn tail from mid-file damage, and reports what it lost. |
| Generation journal | [`generation_store.h`](include/wanrep/generation_store.h) | The record of which generations exist. One append plus one `fsync` is what makes a generation real. |
| Store lifecycle | [`target_store.h`](include/wanrep/target_store.h) | Opens a store, probes whether the filesystem actually enforces the locking the store depends on, and provides `verify()`, the one oracle every failure test ends with. |
| Protocol | [`protocol.h`](include/wanrep/protocol.h) | The target's state machine, and the source's three-stage pipeline: read and batch, compress on several threads, write to the socket from one. |
| Queues | [`spsc_ring.h`](include/wanrep/spsc_ring.h), [`mpmc_queue.h`](include/wanrep/mpmc_queue.h) | Bounded queues between pipeline stages. Uncontended push and pop take no lock; a full queue blocks the producer, which is how memory stays bounded regardless of tree size. |
| Transport | [`link.h`](include/wanrep/link.h), [`tcp_link.h`](include/wanrep/tcp_link.h) | An abstract byte link, TCP, and an in-memory link for tests. All socket access goes through loops that tolerate short reads and writes. |
| Link emulation | [`wan_link.h`](include/wanrep/wan_link.h), [`fault_link.h`](include/wanrep/fault_link.h) | Adds a fixed round-trip delay and a bandwidth ceiling, or drops and corrupts the connection at named points. |

### A transfer, end to end

```
 source                                                        target
 ------                                                        ------
 scan the tree: cut files into
 chunks, hash each chunk, build
 the manifest
                    ---- HELLO (version, chunk parameters) --->
                    <--- HELLO_ACK ----------------------------

                    ---- SESSION_START + manifest ------------>
                                                               verify the manifest's own
                                                               digest, derive the chunk
                                                               numbering, ask the local
                                                               store which chunks are
                                                               missing
                    <--- NEED {1, 2, 500-502} ----------------
 read those chunks, pack them into
 batches, compress each batch,
 frame it
                    ---- CHUNKS ----------------------------->  check the frame, decompress,
                    ---- CHUNKS ----------------------------->  re-hash every chunk and
                    ---- CHUNKS ----------------------------->  reject any that does not
                       (streamed, no per-chunk acks)            match its name, then append
                                                                it to the store

                    ---- GEN_COMMIT ------------------------->  confirm nothing is missing,
                                                                then make the generation
                                                                durable
                    <--- COMMIT_ACK --------------------------
```

Three points in that exchange carry most of the design.

**The chunk numbering is never transmitted.** Both sides walk the same manifest with the
same rule (files in order, chunks in order, each new name takes the next index) and so
arrive at the same numbering independently. That lets the target reply with small integers,
run-length encoded, instead of a list of 32-byte names. The target verifies the manifest's
digest before it numbers anything, so the two sides cannot be numbering different bytes.

**The target decides what it needs by looking at its store**, not by comparing the new
manifest to the previous one. Comparing manifests is faster and wrong: if a stored chunk is
lost or silently corrupted, the file it belongs to still looks unchanged, so the damage
would never be repaired. Probing the store costs a hash lookup per chunk and makes the
system self-healing.

**The target never trusts the sender.** Every chunk is re-hashed on arrival and discarded
if it does not match the name it claims, which collapses a buggy sender, a corrupted
network and a hostile peer into one case handled in one place.

### How a snapshot becomes durable

The target's rule is narrow: a generation exists if, and only if, its commit record is
durable in the journal. Not when its chunks arrive, and not when its manifest is written.

```
store/
  TARGET                              store header
  LOCK                                held for the lifetime of the process
  chunks/c00000000.dat                [CHNK][len][crc][sha-256][bytes] records, appended
  datasets/<name>/manifests/
    g0000000007.man                   one manifest per generation
  GENERATIONS                         append-only: "generation N of dataset D is committed"
```

A commit runs in this order, and the order is the whole mechanism:

1. Check that every requested chunk actually arrived. If anything is missing, refuse.
2. `fsync` the chunk containers, so the data is physically on disk.
3. Write the manifest with the temp-file, `fsync`, rename, `fsync` the directory sequence.
   It is now durable but invisible, because nothing names it yet.
4. Append one commit record to `GENERATIONS` and `fsync`. This is the instant the
   generation starts to exist.
5. Only now acknowledge to the source.

The property that makes this work is that nothing durable is ever allowed to point at
something that is not yet durable, and that every step is safe to repeat. Committing a
generation that is already committed, with the same content, succeeds and changes nothing;
committing one with different content is refused, because a committed generation is
immutable.

### What happens when something breaks

**The connection drops.** The source reconnects and the target runs the set difference
again against its own store. Chunks that arrived before the drop are already there and are
not requested again, in whatever order they happened to land. There is no saved position
anywhere: the target does not remember how far it got, it looks at what it holds. A known
session saves re-sending the manifest, and that is all it saves. An earlier design did
remember a position and was measurably slower than the fallback it was meant to beat, which
is written up as B7 in the [bug journal](docs/CHALLENGES.md).

**The target process is killed.** On restart, the journal is read record by record and
stops at the first one that fails its checksum, so a half-written commit record leaves the
generation nonexistent rather than half-applied. A manifest that no commit record names is
deleted. Chunks that arrived but were never committed are kept, because they are valid data
that nothing points at, and the next attempt finds them already present.

**A chunk record does not parse.** That is either a torn tail, from a crash during an
append, or damage in the middle of a container from a bad sector. The two are
indistinguishable from the record itself, so recovery scans forward for the next record
that fully validates. Finding one proves this was not the end of the file, so only the
damaged span is skipped, the rest is kept, and the loss is recorded where `verify()` will
report it. Finding none means it really was a torn tail, and the container is truncated
there. An early version always truncated and so destroyed good data; that is B4 in the bug
journal, and it is the reason `verify()` counts recovery damage as a problem.

## Using it as a library

Everything is header-only, so the public API is whatever you include. The examples below
are the real entry points; the CLI in [`src/main.cpp`](src/main.cpp) is a thin wrapper over
the same calls and is worth reading as a longer example.

### Adding it to a build

Put `include/` on your include path, compile as C++20, and link `pthread`.

```cmake
add_executable(myapp main.cpp)
target_include_directories(myapp PRIVATE path/to/wanrep/include)
target_compile_features(myapp PRIVATE cxx_std_20)
target_link_libraries(myapp PRIVATE pthread)
```

The code targets Linux. It uses `flock`, `fsync` on directories, `MSG_NOSIGNAL`, and
`AT_HWCAP` for CPU feature detection.

### Replicating a tree

```cpp
#include "wanrep/protocol.h"
#include "wanrep/tcp_link.h"

using namespace wanrep;

auto link = TcpLink::connect("backup.example.com", 9000);
if (!link.ok()) return fail(link.error());

SourceJob::Options opt;
opt.dataset = "nightly";
opt.generation = 7;             // the caller owns generation numbering
opt.compress = true;
opt.compressor_threads = 2;

auto stats = SourceJob::run(**link, "/srv/data", opt);
if (!stats.ok()) return fail(stats.error());

std::printf("%llu bytes on the wire, %zu of %zu chunks sent, %zu round trips\n",
            (unsigned long long)stats->wire_bytes_out,
            stats->chunks_sent, stats->chunks_total, stats->round_trips);
```

`JobStats` reports `wire_bytes_out` from the link's own counter, so it includes all protocol
overhead rather than estimating from chunk sizes. It also separates
`payload_bytes_sent` from `compressed_bytes_sent`, which is how you tell dedup's
contribution from compression's.

### Surviving a dropped connection

`run_resilient` takes a factory instead of a link, reconnects when the link fails, and
resumes. It scans the tree once and reuses that scan across attempts.

```cpp
auto dial = []() -> Result<std::shared_ptr<Link>> {
  auto l = TcpLink::connect("backup.example.com", 9000);
  if (!l.ok()) return l.error();
  return std::shared_ptr<Link>(*l);
};

int attempts = 0;
auto stats = SourceJob::run_resilient(dial, "/srv/data", opt, /*max_attempts=*/6, &attempts);
if (!stats.ok()) return fail(stats.error());
std::printf("completed in %d attempt(s), resumed=%s\n", attempts, stats->resumed ? "yes" : "no");
```

### Running a target

```cpp
#include "wanrep/protocol.h"
#include "wanrep/target_store.h"
#include "wanrep/tcp_link.h"

auto store    = TargetStore::open("/var/lib/wanrep");
auto sessions = SessionJournal::open("/var/lib/wanrep");
auto listener = TcpLink::Listener::bind("0.0.0.0", 9000);
if (!store.ok() || !sessions.ok() || !listener.ok()) return 1;

for (;;) {
  auto conn = listener->accept();
  if (!conn.ok()) return fail(conn.error());

  TargetServer server(**store, **sessions);
  auto r = server.serve(**conn);
  // A broken link is an ordinary outcome here, not a reason to stop serving.
  if (!r.ok()) std::fprintf(stderr, "connection ended: %s\n", r.error().message().c_str());
  (*conn)->close();
}
```

`TargetStore::open` recovers the store before it returns: containers are scanned, the index
is rebuilt, torn tails are truncated, and manifests that no commit record names are
removed. It also probes the filesystem for working `flock` exclusion and refuses to open
where that probe fails, which is deliberate. On one bind-mounted filesystem, two processes
could both take an exclusive lock with no error at all (B2 in the bug journal), and a store
whose single-writer guarantee is silently absent is worse than one that will not open.

### Reading, verifying and restoring a store

```cpp
auto store = TargetStore::open("/var/lib/wanrep");

for (const std::string& ds : (*store)->generations().datasets()) {
  auto gens = (*store)->generations().visible_generations(ds);
  bool prefix_ok = (*store)->generations().is_prefix_consistent(ds);
  std::printf("%s: %zu generations, prefix-consistent=%s\n",
              ds.c_str(), gens.size(), prefix_ok ? "yes" : "no");
}

// Full check: every chunk's CRC and content hash, every committed manifest's digest,
// the prefix-consistency invariant, and anything recovery reported as damaged.
auto report = (*store)->verify(/*deep=*/true);
if (!report.ok()) return fail(report.error());
if (!report->ok()) {
  for (const auto& problem : report->detail) std::printf("  %s\n", problem.c_str());
}

// Rebuild a generation's files on disk.
auto bytes = (*store)->generations().manifest_bytes("nightly", 7);
auto manifest = Manifest::decode(ByteSpan(bytes->data(), bytes->size()));
auto r = materialize(*manifest, (*store)->chunks(), "/tmp/restore");
```

`materialize` writes the files; checking them against the manifest's whole-file digests is
the caller's job, and the test suite does exactly that before comparing the restored tree
to the original with `diff -r`.

### Using the chunker on its own

The chunker is independent of everything else and is stateless by design, so chunking a
buffer in one call and chunking the same bytes in many small reads must produce identical
boundaries.

```cpp
#include "wanrep/chunker.h"
#include "wanrep/sha256.h"

Chunker chunker;                      // 2 KiB min, 8 KiB average, 64 KiB max
ByteSpan rest(data.data(), data.size());

while (!rest.empty()) {
  size_t n = chunker.next_cut(rest, /*at_eof=*/true);   // 0 means "needs more data"
  ByteSpan chunk = rest.subspan(0, n);
  Digest32 name = sha256(chunk);
  // ... store or send it ...
  rest = rest.subspan(n);
}
```

For streaming, pass `at_eof=false` and treat a return of `0` as a request for more bytes.
`chunk_all()` exists for callers that already hold the whole buffer, and the test suite
uses it as a differential check against the streaming path.

### Testing against a slow link

`WanLink` wraps any link and adds a fixed round-trip delay plus a token-bucket bandwidth
ceiling. It is deterministic given a seed, which is what makes latency tests reproducible.

```cpp
#include "wanrep/wan_link.h"

auto tcp = TcpLink::connect("127.0.0.1", 9000);

WanLink::Params p;
p.rtt_ms = 100.0;           // full round trip; half is applied in each direction
p.bandwidth_mbps = 100.0;   // megabits per second, the unit links are sold in
p.jitter_ms = 0.0;          // 0 disables jitter; otherwise seed it for reproducibility

auto wan = WanLink::create(std::static_pointer_cast<Link>(*tcp), p);
if (!wan.ok()) return fail(wan.error());

auto stats = SourceJob::run(**wan, "/srv/data", opt);
```

Watch `round_trips` rather than the byte count when you do this. Round trips, not bytes,
are what the delay multiplies.

### Error handling

The project does not use exceptions. Fallible calls return `Result<T>`, which is marked
`[[nodiscard]]`, so ignoring an error is a compile error rather than a silent bug. The two
shapes you will write are:

```cpp
auto r = store.put(name, bytes);
if (!r.ok()) return r.error();        // inspect r.error().code() / .message()

WANREP_TRY(store.sync());             // the same thing in one line
```

A dropped link, a bad checksum and a malformed frame are ordinary outcomes on these paths,
not exceptional ones, and the error codes keep them distinguishable: a peer that closed
cleanly and a peer that was killed are different situations, and resume branches on the
difference.

## Command line

```
wanrep target serve       --store <dir> --listen <host:port> [--once]
wanrep target ls          --store <dir> [--dataset <name>]
wanrep target materialize --store <dir> --dataset <name> --gen <n> --out <dir>
wanrep target verify      --store <dir> [--deep]
wanrep source replicate   --tree <dir> --peer <host:port> --dataset <name>
                          [--gen <n>] [--rtt <ms>] [--bw <Mbit/s>]
```

A full round trip, from two shells inside the container:

```bash
# shell 1
./scripts/dev.sh ./build-none/wanrep target serve --store /tmp/store --listen 127.0.0.1:9000

# shell 2
./scripts/dev.sh ./build-none/wanrep source replicate --tree ./docs --peer 127.0.0.1:9000 --dataset docs
./scripts/dev.sh ./build-none/wanrep target verify --store /tmp/store --deep
./scripts/dev.sh ./build-none/wanrep target materialize --store /tmp/store --dataset docs --gen 0 --out /tmp/out
```

Add `--rtt 100 --bw 100` to `source replicate` to put the transfer behind the link
emulator. Keep stores on container-local storage, not on a bind mount, for the locking
reason described above.

## Building and running the tests

Everything builds and runs on Linux in Docker. That is not incidental: the behaviour this
code depends on is operating-system behaviour, including short writes on sockets, `SIGPIPE`
on a dead peer, the difference between an orderly close and an abortive one, `fsync`
ordering and `flock` semantics, and macOS and Linux disagree on several of them.

```bash
git clone https://github.com/alladikarthik02/Distributed-Replication-System-Across-Wide-Area-Links.git
cd Distributed-Replication-System-Across-Wide-Area-Links
./scripts/dev.sh ./scripts/check.sh
```

That builds and runs all 14 suites three times: ordinary `-O2`, ASan with UBSan, and TSan.
It is three build trees because ASan and TSan cannot coexist in one binary. For a single
configuration:

```bash
./scripts/dev.sh ./scripts/check.sh none
```

Randomized tests print their seed, and a failure can be replayed exactly:

```bash
WANREP_SEED=0x9e3779b97f4a7c15 ./scripts/dev.sh ./build-none/test_harness
```

`./scripts/dev.sh` with no arguments gives an interactive shell in the container, with the
repository bind-mounted so edits stay on the host.

## Measurements

Bandwidth reduction depends as much on the data as on the code, so the benchmark prints its
workload above every number and reports several figures instead of one convenient one.

| Scenario | Result |
|---|---|
| First sync to an empty target | 52.8% fewer bytes than a full transfer |
| Later generations of a slowly changing tree | 98.9% fewer |
| Eight generations, as a campaign | 93.0% fewer |
| Cost of a link drop mid-transfer | 8.7% more than an uninterrupted run; a restart would be 100% more |
| Same case with the session file deleted | still 38% of a full transfer, because the target checks its store rather than its notes |
| Round trips per generation | 3 to 5, independent of tree size |
| Chunking plus SHA-256, one thread | 966 MB/s |

Two results from that set are worth reading in full in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md). The first sync's saving comes almost entirely
from compression rather than deduplication, which the attribution table shows plainly
rather than leaving to the reader's assumption. And the lock-free queues, measured against
a mutex baseline with realistic per-item work, deliver the same throughput and a
substantially better worst-case push latency, so the claim made for them here is about
blocking behaviour and bounded memory, not speed.

## Limitations

- Replication is one-way. There is no bidirectional sync and no conflict resolution.
- There is no security. CRCs catch accidents, not attackers. What limits a hostile peer is
  the fixed size bounds, a decompressor that validates every instruction before executing
  it, and the content-hash check on every chunk that arrives. There is no encryption and no
  authentication.
- Chunks that no generation references are never reclaimed. There is no garbage collector.
- The source does not snapshot. A file modified while it is being read can be captured as a
  mix of old and new content.
- Deduplication is chunk-granular. There is no byte-level delta within a chunk.
- The chunk index is held in memory, and has not been measured at a size where that becomes
  the limiting factor.
- Durability testing covers process crashes, not power loss. The tests kill processes with
  `SIGKILL` and verify the store afterwards, which is a real guarantee but a different one.

## Repository layout

```
include/wanrep/     the implementation, header-only
src/main.cpp        the command-line tool
tests/              14 suites, including adversarial input and fuzz cases
bench/              chunker, hash, compressor, queue and wire-byte benchmarks
tools/faultrunner   forks a real target process and kills it mid-write
scratch/            two small probes that settled platform questions
scripts/dev.sh      run a command inside the container
scripts/check.sh    build and test in all three configurations
docs/               specification, bug journal, measurements
```

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) is the design document: the consistency contract, the wire
  protocol, the safety requirements with the test that proves each one, and a section on
  where the design is weak.
- [`docs/CHALLENGES.md`](docs/CHALLENGES.md) is a bug journal. Each entry runs from symptom
  through the hypotheses considered, including the wrong ones, to the root cause, the fix,
  and what the fix generalizes to. Three entries stand on their own:
  - **B4**, where recovery was deleting good data, and `verify()` called the store clean
    afterwards because nothing was left to be wrong about.
  - **B7**, where the resume fast path turned out slower than the fallback it was
    optimizing, and the signal was a correct fix that moved the number by one percent.
  - **B8**, where two fault-injection cases passed without injecting anything, caught only
    because the runner printed how each child process died.
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) records every measurement with the command
  that produced it and the workload it ran on, including the controls that are designed to
  fail.

## License

BSD 3-Clause. See [`LICENSE`](LICENSE).
