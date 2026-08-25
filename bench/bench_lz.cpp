// In-transit compression: ratio and throughput per content class, plus the batch-size
// curve. Not a pass/fail gate -- a measurement, recorded in docs/BENCHMARKS.md with the
// command that produced it.
//
// WHY THESE THREE NUMBERS AND NOT JUST THE RATIO:
//   The project claims compression REDUCES bandwidth. That is only true if the
//   compressor outruns the link: a stage that runs at 8 MB/s in front of a 12.5 MB/s
//   WAN link is not a bandwidth reduction, it is a bandwidth reduction that costs
//   bandwidth, because the link idles while we think (SPEC 3.4). So compress MB/s and
//   decompress MB/s are reported next to the ratio, always, with the link speed printed
//   in the same units so the comparison is impossible to fudge.
//
// WHY THE BATCH-SIZE CURVE IS HERE:
//   SPEC 3.4 rule 3 says "compress batches, not chunks" -- an 8 KiB chunk compressed
//   alone wastes the dictionary. That is a claim, and this is the measurement that
//   decides it. The same corpus is compressed as independent 8/16/64/256/1024 KiB
//   blocks and the aggregate ratio is printed for each, together with the MARGINAL gain
//   per step -- because "bigger is better" is not a decision, "the next doubling buys
//   7%" is. The curve also has a structural ceiling worth naming out loud: the match
//   offset is a 2-byte field, so no batch size can reference further than 64 KiB back.
//   Past that point the remaining gain is only "more candidate pairs land inside the
//   same 64 KiB window" plus amortized token overhead, and the measured marginal column
//   shows exactly that shape.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <vector>

#include "wanrep/lz.h"
#include "wanrep/types.h"

using namespace wanrep;

namespace {

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
  uint32_t below(uint32_t n) { return static_cast<uint32_t>(next() % n); }
  uint8_t byte() { return static_cast<uint8_t>(next() >> 24); }
};

double mbps(size_t bytes, double seconds) {
  return static_cast<double>(bytes) / seconds / (1024.0 * 1024.0);
}

double now_delta(std::chrono::steady_clock::time_point t0) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

// --- content classes -------------------------------------------------------------
// The same five the test suite uses, so a ratio quoted here and a ratio quoted there
// mean the same thing.

std::vector<uint8_t> random_bytes(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = rng.byte();
  return v;
}

std::vector<uint8_t> text_like(size_t n, uint64_t seed) {
  static const char* kWords[] = {"replication ", "chunk ", "manifest ", "generation ",
                                 "target ", "source ", "fingerprint ", "commit ",
                                 "the ", "a ", "of ", "and ", "durable ", "sequence "};
  Rng rng(seed);
  std::vector<uint8_t> v;
  v.reserve(n + 32);
  while (v.size() < n) {
    const char* w = kWords[rng.below(14)];
    for (const char* p = w; *p; p++) v.push_back(static_cast<uint8_t>(*p));
    if (rng.below(16) == 0) v.push_back('\n');
  }
  v.resize(n);
  return v;
}

std::vector<uint8_t> log_lines(size_t n, uint64_t seed) {
  static const char* kLevels[] = {"INFO ", "WARN ", "ERROR ", "DEBUG "};
  static const char* kMsgs[] = {"chunk stored fp=", "manifest fsynced gen=",
                                "session resumed hwm=", "frame crc ok seq=",
                                "commit durable gen="};
  Rng rng(seed);
  std::vector<uint8_t> v;
  v.reserve(n + 128);
  uint64_t t = 1'700'000'000;
  while (v.size() < n) {
    char line[160];
    const int k = std::snprintf(line, sizeof(line), "2026-08-24T%02u:%02u:%02u.%03uZ %s%s%llu\n",
                                rng.below(24), rng.below(60), rng.below(60), rng.below(1000),
                                kLevels[rng.below(4)], kMsgs[rng.below(5)],
                                static_cast<unsigned long long>(t++));
    for (int i = 0; i < k; i++) v.push_back(static_cast<uint8_t>(line[i]));
  }
  v.resize(n);
  return v;
}

std::vector<uint8_t> structured_records(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v;
  v.reserve(n + 64);
  uint32_t id = 0;
  while (v.size() < n) {
    const uint8_t tag[8] = {'C', 'H', 'N', 'K', 0, 0, 0, 0};
    for (uint8_t b : tag) v.push_back(b);
    for (int i = 0; i < 4; i++) v.push_back(static_cast<uint8_t>(id >> (8 * i)));
    id++;
    for (int i = 0; i < 44; i++) v.push_back(0);
    for (int i = 0; i < 8; i++) v.push_back(rng.byte());
  }
  v.resize(n);
  return v;
}

// A stand-in for what actually crosses this link: a stream of "files", most of which are
// near-duplicates of an earlier one (a backup tree re-scanned), interleaved with a
// minority of genuinely incompressible blobs (already-compressed media). This is the
// corpus for the batch-size curve, because the redundancy it contains lives ACROSS
// chunk boundaries -- which is exactly the redundancy an 8 KiB-at-a-time compressor
// cannot see.
std::vector<uint8_t> backup_like(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<std::vector<uint8_t>> pool;
  for (int i = 0; i < 24; i++) pool.push_back(text_like(4000 + rng.below(9000), rng.next()));

  std::vector<uint8_t> v;
  v.reserve(n + 65536);
  while (v.size() < n) {
    if (rng.below(10) == 0) {
      const auto blob = random_bytes(2000 + rng.below(6000), rng.next());
      v.insert(v.end(), blob.begin(), blob.end());
      continue;
    }
    auto f = pool[rng.below(static_cast<uint32_t>(pool.size()))];
    // A handful of edits, so it is a near-duplicate rather than an identical copy.
    for (int e = 0, edits = 1 + static_cast<int>(rng.below(4)); e < edits; e++) {
      f[rng.below(static_cast<uint32_t>(f.size()))] = rng.byte();
    }
    v.insert(v.end(), f.begin(), f.end());
  }
  v.resize(n);
  return v;
}

// --- the measurement itself -------------------------------------------------------

struct BatchResult {
  size_t blocks = 0;
  size_t declined = 0;   // blocks where rule 1 fired: sent raw
  size_t wire_bytes = 0; // what actually crosses the link (compressed, or raw when declined)
  double comp_s = 0;
  double decomp_s = 0;
};

// Compresses `data` as independent blocks of `batch`, decompresses them all back, and
// times each direction separately.
BatchResult run(const std::vector<uint8_t>& data, size_t batch, int reps) {
  BatchResult r;
  std::vector<uint8_t> scratch(lz::max_compressed_size(batch) + 64);
  std::vector<uint8_t> out(batch);

  // Pass 0, untimed: produce and VERIFY every block. Verification is not optional in a
  // benchmark -- a codec that is fast because it is wrong would otherwise print the best
  // numbers on the page. This pass also does all the allocation, so the timed loops
  // below measure the codec and not the allocator (which is what made the first draft of
  // this benchmark report a 3x spread between runs).
  std::vector<std::vector<uint8_t>> blocks;
  blocks.reserve(data.size() / batch + 1);
  for (size_t off = 0; off < data.size(); off += batch) {
    const size_t len = std::min(batch, data.size() - off);
    const size_t k =
        lz::compress(ByteSpan(data.data() + off, len), scratch.data(), scratch.size());
    r.blocks++;
    if (k == 0) {
      r.declined++;
      r.wire_bytes += len;  // raw fallback, SPEC S14 rule 1
      blocks.emplace_back();
      continue;
    }
    r.wire_bytes += k;
    blocks.emplace_back(scratch.begin(), scratch.begin() + static_cast<ptrdiff_t>(k));
    auto d = lz::decompress(ByteSpan(blocks.back().data(), k), out.data(), out.size());
    if (!d.ok() || *d != len || std::memcmp(out.data(), data.data() + off, len) != 0) {
      std::fprintf(stderr, "FATAL: round-trip mismatch at offset %zu -- every number "
                           "below would be meaningless\n", off);
      std::exit(1);
    }
  }

  for (int rep = 0; rep < reps; rep++) {
    size_t produced = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (size_t off = 0; off < data.size(); off += batch) {
      const size_t len = std::min(batch, data.size() - off);
      const size_t k =
          lz::compress(ByteSpan(data.data() + off, len), scratch.data(), scratch.size());
      produced += (k == 0) ? len : k;
    }
    const double s = now_delta(t0);
    if (rep == 0 || s < r.comp_s) r.comp_s = s;
    // Consuming the result keeps the optimizer from deleting the loop, and comparing it
    // against pass 0 re-checks that compress() is a pure function of its input -- the
    // property the persistent hash table in lz.h has to earn.
    if (produced != r.wire_bytes) {
      std::fprintf(stderr, "FATAL: compress() is not deterministic across runs\n");
      std::exit(1);
    }
  }

  for (int rep = 0; rep < reps; rep++) {
    const auto t0 = std::chrono::steady_clock::now();
    for (const auto& blk : blocks) {
      if (blk.empty()) continue;  // raw on the wire; the target just memcpys it
      auto d = lz::decompress(ByteSpan(blk.data(), blk.size()), out.data(), out.size());
      if (!d.ok()) std::exit(1);  // impossible: pass 0 already decoded every one
    }
    const double s = now_delta(t0);
    if (rep == 0 || s < r.decomp_s) r.decomp_s = s;
  }
  return r;
}

double ratio_of(const BatchResult& r, size_t raw) {
  return static_cast<double>(raw) / static_cast<double>(r.wire_bytes);
}

}  // namespace

int main() {
  constexpr uint64_t kSeed = 0x9e3779b97f4a7c15ull;
  constexpr size_t kN = 32u << 20;         // 32 MiB per content class
  constexpr size_t kDefaultBatch = 256u << 10;  // SPEC 3.4's proposed batch size
  constexpr int kReps = 5;                 // best of 5: these runs are short enough for scheduler noise to show

  std::printf("wanrep T3 -- in-transit compression (SPEC 3.4)\n");
  std::printf("corpus: %zu MiB per class, compressed as independent %zu KiB batches, "
              "best of %d\n\n", kN >> 20, kDefaultBatch >> 10, kReps);

  struct Class { const char* name; std::vector<uint8_t> (*gen)(size_t, uint64_t); };
  const Class classes[] = {
      {"text-like", text_like},
      {"log lines", log_lines},
      {"structured binary", structured_records},
      {"backup-like mix", backup_like},
      {"incompressible", random_bytes},
  };

  std::printf("%-20s %8s %8s %14s %14s  %s\n", "content class", "ratio", "saved",
              "compress", "decompress", "raw fallback");
  std::printf("%-20s %8s %8s %14s %14s  %s\n", "-------------", "-----", "-----",
              "--------", "----------", "------------");

  for (const auto& c : classes) {
    const auto data = c.gen(kN, kSeed);
    const auto r = run(data, kDefaultBatch, kReps);
    const double ratio = ratio_of(r, kN);

    // A class where every block was declined never entered the decoder, so there is no
    // decompression throughput to report. Printing bytes/0-seconds would be a made-up
    // number -- and a spectacular one, which is exactly how made-up numbers survive.
    char dec[24];
    if (r.declined == r.blocks) {
      std::snprintf(dec, sizeof(dec), "%13s", "n/a (raw)");
    } else {
      std::snprintf(dec, sizeof(dec), "%8.1f MB/s", mbps(kN, r.decomp_s));
    }
    char comp[24];
    std::snprintf(comp, sizeof(comp), "%8.1f MB/s", mbps(kN, r.comp_s));

    std::printf("%-20s %7.2fx %7.1f%% %14s %14s  %zu/%zu blocks\n", c.name, ratio,
                100.0 * (1.0 - 1.0 / ratio), comp, dec, r.declined, r.blocks);
  }
  std::printf("\nThe incompressible row is the miss-streak skip doing its job: rule 1's "
              "\"give up\" path\nnever finishes the block, so declining costs a fraction "
              "of what compressing would.\n");

  // --- the batch-size curve (SPEC 3.4 rule 3) --------------------------------------
  std::printf("\nbatch size vs ratio, on the backup-like corpus (%zu MiB).\n", kN >> 20);
  std::printf("This is the measurement behind \"compress batches, not chunks\": the "
              "8 KiB row is\nwhat compressing each chunk on its own would cost.\n\n");
  std::printf("%12s %8s %8s %8s %10s %14s %14s\n", "batch", "blocks", "ratio", "saved",
              "vs prev", "compress", "decompress");
  std::printf("%12s %8s %8s %8s %10s %14s %14s\n", "-----", "------", "-----", "-----",
              "-------", "--------", "----------");

  const auto corpus = backup_like(kN, kSeed);
  const size_t batches[] = {8u << 10, 16u << 10, 64u << 10, 256u << 10, 1024u << 10};
  double first_ratio = 0, prev_ratio = 0, last_ratio = 0;
  for (size_t b : batches) {
    const auto r = run(corpus, b, kReps);
    const double ratio = ratio_of(r, kN);
    if (first_ratio == 0) first_ratio = ratio;

    // The marginal column is the one that answers the actual question. "Bigger batches
    // compress better" is not a decision; "the next doubling buys 3%" is.
    char marginal[16];
    if (prev_ratio == 0) {
      std::snprintf(marginal, sizeof(marginal), "%9s", "-");
    } else {
      std::snprintf(marginal, sizeof(marginal), "%+8.1f%%",
                    100.0 * (1.0 - prev_ratio / ratio));
    }
    char comp[24], dec[24];
    std::snprintf(comp, sizeof(comp), "%8.1f MB/s", mbps(kN, r.comp_s));
    std::snprintf(dec, sizeof(dec), "%8.1f MB/s", mbps(kN, r.decomp_s));

    std::printf("%9zu KiB %8zu %7.2fx %7.1f%% %10s %14s %14s\n", b >> 10, r.blocks,
                ratio, 100.0 * (1.0 - 1.0 / ratio), marginal, comp, dec);
    prev_ratio = ratio;
    last_ratio = ratio;
  }
  std::printf("\n8 KiB -> %zu KiB moved the ratio %.2fx -> %.2fx, i.e. it removed %.1f%% "
              "of the bytes\nthat per-chunk compression would still have put on the "
              "wire.\n", batches[std::size(batches) - 1] >> 10, first_ratio, last_ratio,
              100.0 * (1.0 - first_ratio / last_ratio));
  std::printf("Read the \"vs prev\" column, not the ratio column: past 64 KiB no NEW "
              "distance becomes\nreachable -- the match offset is a 2-byte field, so the "
              "window is pinned at 64 KiB --\nand what is left is more candidate pairs "
              "landing inside that window plus amortized\ntoken overhead. That is why "
              "the marginal gain per doubling collapses even though the\nratio column "
              "keeps creeping up, and it is the reason SPEC 3.4 batches at 256 KiB "
              "rather\nthan at the largest size that still helps.\n");

  // --- context ---------------------------------------------------------------------
  std::printf("\nfor reference: 100 Mbit/s = %.1f MB/s, 1 Gbit/s = %.1f MB/s. A "
              "compressor slower than\nthe link is a bandwidth reduction that costs "
              "bandwidth (SPEC 3.4).\n", 100.0 / 8.0, 1000.0 / 8.0);
  return 0;
}
