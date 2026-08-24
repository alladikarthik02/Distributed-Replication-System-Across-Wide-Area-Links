// T1 measurement: how fast are the fingerprint and integrity primitives?
//
// This matters for SPEC R3.3 ("tuned the chunking and indexing path"): the
// runtime-dispatched hardware CRC path is an optimization, and an optimization
// without a number does not go into this project. It also sets the ceiling for
// the whole ingest path -- ingest can never be faster than its hash.
#include <cstdint>
#include <cstdio>
#include <chrono>
#include <random>
#include <string>
#include <vector>

#include "wanrep/crc32c.h"
#include "wanrep/sha256.h"

using namespace wanrep;
using Clock = std::chrono::steady_clock;

namespace {

// Best-of-N rather than mean: we want the machine's capability, and every
// perturbation (scheduler, page fault, another container) only ever makes a
// sample slower. The minimum is the least-noisy estimator here.
template <class F>
double best_mb_per_s(const std::vector<uint8_t>& data, int reps, F&& f) {
  double best = 0;
  for (int r = 0; r < reps; r++) {
    const auto t0 = Clock::now();
    const uint64_t sink = f(data);
    const double secs = std::chrono::duration<double>(Clock::now() - t0).count();
    // Keep the compiler from deleting the work we are timing.
    asm volatile("" ::"r"(sink) : "memory");
    if (secs > 0) best = std::max(best, (data.size() / 1048576.0) / secs);
  }
  return best;
}

void row(const char* name, double mb_s) {
  std::printf("  %-26s %8.1f MB/s\n", name, mb_s);
}

}  // namespace

int main() {
  std::mt19937_64 rng(12345);
  const size_t kSize = 64u << 20;  // 64 MiB -- far past any cache
  std::vector<uint8_t> data(kSize);
  for (auto& b : data) b = static_cast<uint8_t>(rng() & 0xFF);

  std::printf("wanrep T1 primitives (carried from dedupe)  (buffer = %zu MiB, best of 5)\n", kSize >> 20);
  std::printf("  hardware CRC32C: %s   hardware SHA-2: %s\n\n",
              crc32c_has_hardware() ? "available" : "NOT available",
              sha256_has_hardware() ? "available" : "NOT available");

  row("sha256 (scalar)", best_mb_per_s(data, 5, [](const std::vector<uint8_t>& d) {
        return static_cast<uint64_t>(sha256(d, HashBackend::kScalar)[0]);
      }));

  if (sha256_has_hardware()) {
    row("sha256 (ARMv8 SHA-2)", best_mb_per_s(data, 5, [](const std::vector<uint8_t>& d) {
          return static_cast<uint64_t>(sha256(d, HashBackend::kHardware)[0]);
        }));
  }

  row("crc32c (table, sw)", best_mb_per_s(data, 5, [](const std::vector<uint8_t>& d) {
        return static_cast<uint64_t>(crc32c_table(d));
      }));

#if defined(__aarch64__)
  if (crc32c_has_hardware()) {
    row("crc32c (hardware)", best_mb_per_s(data, 5, [](const std::vector<uint8_t>& d) {
          return static_cast<uint64_t>(crc32c_hardware(d));
        }));
  }
#endif

  // The bitwise reference is ~1 bit per iteration; run it on a small slice so
  // the benchmark finishes this decade. Reported to show why it is a test oracle
  // and never a production path.
  std::vector<uint8_t> small(data.begin(), data.begin() + (1u << 20));
  row("crc32c (bitwise, oracle)", best_mb_per_s(small, 3, [](const std::vector<uint8_t>& d) {
        return static_cast<uint64_t>(crc32c_bitwise(d));
      }));

  return 0;
}
