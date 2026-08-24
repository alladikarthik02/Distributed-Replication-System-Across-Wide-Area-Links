// Spike: why does a long run of ONE byte value always produce max-size chunks?
//
// Derivation to check empirically. On a constant run the Gear recurrence is
//   h_0 = 0,  h_{k+1} = (h_k << 1) + G      where G = gear[b]
// which unrolls to  h_k = (2^k - 1) * G  (mod 2^64).
// For k >= 64, 2^k = 0 (mod 2^64), so h_k = -G FOREVER. The hash does not merely
// become predictable, it becomes CONSTANT after 64 bytes.
//
// Consequence: for each byte value b, whether a constant run of b ever cuts is decided
// by ONE test -- does (-G) match the mask? -- not by the data. It is all-or-nothing per
// byte value. This checks that against all 256 values.
#include <cstdint>
#include <cstdio>
#include "wanrep/chunker.h"

using namespace wanrep;

int main() {
  const ChunkParams p;
  int cuts_s = 0, cuts_l = 0, cuts_warmup = 0;
  for (int b = 0; b < 256; b++) {
    const uint64_t G = chunk_detail::kGear[b];
    // 1. The steady-state value, reached at k = 64 and held forever after.
    const uint64_t steady = uint64_t{0} - G;  // (2^64 - 1 + 1 - 1)*G == -G
    if ((steady & p.mask_s) == 0) cuts_s++;
    if ((steady & p.mask_l) == 0) cuts_l++;

    // 2. The warm-up: k = 1..63, before the hash freezes. A cut here is the only way a
    //    constant run can produce a chunk shorter than max.
    uint64_t h = 0;
    for (int k = 1; k < 64; k++) {
      h = (h << 1) + G;
      const uint64_t mask = (k + p.min <= p.avg) ? p.mask_s : p.mask_l;
      if ((h & mask) == 0) { cuts_warmup++; break; }
    }
    // 3. Confirm the closed form matches the iterated recurrence.
    uint64_t iter = 0;
    for (int k = 0; k < 200; k++) iter = (iter << 1) + G;
    if (iter != steady) { std::printf("MISMATCH for b=%d: closed form wrong\n", b); return 1; }
  }
  std::printf("closed form h_k = -G for k>=64 : CONFIRMED for all 256 byte values\n");
  std::printf("byte values whose steady hash matches mask_s (15 bits) : %d / 256\n", cuts_s);
  std::printf("byte values whose steady hash matches mask_l (11 bits) : %d / 256\n", cuts_l);
  std::printf("byte values that cut during the 63-byte warm-up        : %d / 256\n", cuts_warmup);
  std::printf("\n=> %d / 256 byte values can EVER cut inside a constant run;\n",
              cuts_warmup + ((cuts_l > 0) ? 1 : 0));
  std::printf("   the rest produce max-size (%u B) chunks, deterministically.\n", p.max);

  // What it means for dedup: are those forced chunks at least identical to each other?
  const std::vector<uint8_t> zeros(1u << 20, 0);
  const Chunker c;
  const auto cs = c.chunk_all(ByteSpan(zeros.data(), zeros.size()));
  bool all_same_len = true;
  for (size_t i = 0; i + 1 < cs.size(); i++)
    if (cs[i].length != cs[0].length) all_same_len = false;
  std::printf("\n1 MiB of zeros -> %zu chunks, all non-tail chunks same length: %s\n",
              cs.size(), all_same_len ? "yes (so all identical => they dedup to ONE chunk)" : "no");
  return 0;
}
