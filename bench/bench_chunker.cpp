// Chunker throughput. Not a pass/fail gate -- a measurement, recorded in
// docs/BENCHMARKS.md with the command that produced it.
//
// Why this number matters for THIS project: chunking and hashing are the only
// CPU-bound work on the source's hot path (SPEC 3.6). If the chunker cannot outrun the
// link, the pipeline's fan-out is pointless and the WAN is no longer the bottleneck --
// which would make every bandwidth-reduction figure a measurement of our own CPU.
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <vector>

#include "wanrep/chunker.h"
#include "wanrep/sha256.h"

using namespace wanrep;

namespace {
std::vector<uint8_t> make_data(size_t n, uint64_t seed) {
  std::vector<uint8_t> v(n);
  uint64_t s = seed;
  for (size_t i = 0; i < n; i++) {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    v[i] = static_cast<uint8_t>(s >> 24);
  }
  return v;
}

double mbps(size_t bytes, double seconds) {
  return static_cast<double>(bytes) / seconds / (1024.0 * 1024.0);
}
}  // namespace

int main() {
  constexpr size_t kN = 256u << 20;  // 256 MiB
  std::printf("generating %zu MiB...\n", kN >> 20);
  const auto data = make_data(kN, 0x9e3779b97f4a7c15ull);
  const ByteSpan span(data.data(), data.size());
  const Chunker c;

  // 1. Chunking alone.
  auto t0 = std::chrono::steady_clock::now();
  const auto chunks = c.chunk_all(span);
  double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("chunk (Gear/FastCDC)      : %8.1f MB/s   (%zu chunks, mean %.0f B)\n",
              mbps(kN, secs), chunks.size(),
              static_cast<double>(kN) / static_cast<double>(chunks.size()));

  // 2. Chunking + fingerprinting: the actual source-side per-byte cost.
  t0 = std::chrono::steady_clock::now();
  size_t pos = 0, count = 0;
  while (pos < data.size()) {
    const size_t len = c.next_cut(span.subspan(pos), true);
    if (len == 0) break;
    volatile auto d = sha256(span.subspan(pos, len));
    (void)d;
    pos += len;
    count++;
  }
  secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("chunk + SHA-256 (auto)    : %8.1f MB/s   (%zu chunks)\n", mbps(kN, secs), count);

  // 3. Context: how fast is a 100 Mbit/s WAN link, in the same units?
  std::printf("\nfor reference: 100 Mbit/s = %.1f MB/s, 1 Gbit/s = %.1f MB/s\n",
              100.0 / 8.0, 1000.0 / 8.0);
  return 0;
}
