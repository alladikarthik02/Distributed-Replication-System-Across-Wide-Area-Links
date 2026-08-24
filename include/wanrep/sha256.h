// PROVENANCE: carried over from project #1 (`dedupe`), commit ac2096a, with the
// namespace and include prefix renamed and nothing else changed. This file is pure,
// dependency-free, already verified against published vectors, and already does runtime
// hardware dispatch -- rewriting it here would produce a second implementation to keep
// correct, not a second piece of learning. Its test suite is carried over with it, so
// the guarantee travels with the code. SPEC 0 records the carry-over.
//
// SHA-256 (FIPS 180-4), implemented in-tree.
//
// WHY IN-TREE AND NOT OpenSSL:
//   Same rule as the rest of this project -- no hidden dependencies. More
//   importantly, a from-scratch implementation is verifiable against the
//   *published NIST vectors*, which is a stronger correctness story than
//   "we linked a library and trusted it". ~200 lines is a cheap price.
//
// WHY SHA-256 AT ALL (and not xxHash/CityHash, which are 10x faster):
//   Content addressing makes "same fingerprint => same bytes" a CORRECTNESS
//   assumption, not a performance one. If two different chunks collide, the
//   engine silently returns the wrong data on restore. With a 256-bit
//   cryptographic digest the accidental-collision probability across 10^15
//   chunks is ~10^-45 -- orders of magnitude below the probability of
//   undetected DRAM/disk corruption, which is the honest comparison. A
//   non-cryptographic hash is trivially collidable, and here a collision is
//   silent data loss. (SPEC 3.2)
//
// ENDIANNESS TRAP:
//   SHA-256 is defined big-endian: message words are loaded big-endian and the
//   digest is emitted big-endian. Our on-disk format (SPEC 3.3) is
//   little-endian. These are different conventions in the same codebase, so
//   every load/store here is explicit, never a memcpy of a uint32_t.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "wanrep/types.h"

#if defined(__aarch64__)
#include <arm_neon.h>
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace wanrep {

// Which implementation of the compression function to use.
//   kAuto     -- hardware if the CPU has it, scalar otherwise. Production.
//   kScalar   -- force the portable C++ path. Used by tests to prove the two
//                agree, and it is the path a machine without the SHA-2
//                extension actually runs.
//   kHardware -- force the ARMv8 path. Tests/benchmarks only; calling this on a
//                CPU without the extension is a SIGILL, so it is never selected
//                implicitly.
enum class HashBackend { kAuto, kScalar, kHardware };

namespace sha_detail {

// FIPS 180-4 4.2.2 -- the 64 round constants: the first 32 bits of the
// fractional parts of the cube roots of the first 64 primes.
inline constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

constexpr uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// --- Portable scalar compression --------------------------------------------
// The reference. Correct everywhere, ~115 MB/s here (measured, bench/bench_hash).
inline void compress_scalar(uint32_t h[8], const uint8_t* block, size_t nblocks) {
  while (nblocks--) {
    uint32_t w[64];
    // Message schedule words 0..15: big-endian loads, spelled out. SHA-256 is
    // big-endian while our on-disk format (SPEC 3.3) is little-endian; mixing
    // the two conventions by memcpy'ing a uint32_t is the classic silent bug.
    for (int i = 0; i < 16; i++) {
      w[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
             (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
             (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
             (static_cast<uint32_t>(block[4 * i + 3]));
    }
    // Words 16..63 are derived -- this is what diffuses a one-bit change across
    // the whole block.
    for (int i = 16; i < 64; i++) {
      const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
      const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const uint32_t ch = (e & f) ^ (~e & g);
      const uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
      const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = S0 + maj;
      hh = g; g = f; f = e;
      e = d + temp1;
      d = c; c = b; b = a;
      a = temp1 + temp2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    block += 64;
  }
}

#if defined(__aarch64__)
// --- ARMv8 SHA-2 extension compression ---------------------------------------
// Three instructions do the work of the whole round loop above: sha256h /
// sha256h2 perform four rounds at a time on the 8-word state held in two NEON
// registers, and sha256su0 / sha256su1 compute four message-schedule words.
//
// The 16 four-round groups follow a strict rotating pattern over MSG0..MSG3 and
// two alternating temporaries. That code was GENERATED from the pattern rather
// than typed, because an index typo here does not fail to compile -- it produces
// a wrong digest, which in a content-addressed store means silently aliasing
// unrelated chunks.
//
// target("+crypto") compiles ONLY this function with the extension enabled, so
// the rest of the binary stays baseline armv8-a and still runs on CPUs without
// it. Selection happens at runtime via AT_HWCAP (SPEC: same pattern as CRC32C).
__attribute__((target("+crypto"))) inline void compress_hw(uint32_t h[8],
                                                           const uint8_t* data,
                                                           size_t nblocks) {
  uint32x4_t STATE0 = vld1q_u32(&h[0]);
  uint32x4_t STATE1 = vld1q_u32(&h[4]);
  uint32x4_t ABEF_SAVE, CDGH_SAVE, MSG0, MSG1, MSG2, MSG3, TMP0, TMP1, TMP2;

  while (nblocks--) {
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;
    // SHA-256 reads message words big-endian; vrev32q_u8 byte-swaps 16 bytes in
    // one instruction.
    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 16)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 32)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 48)));
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0]));

      /* rounds 0-3 */
      MSG0 = vsha256su0q_u32(MSG0, MSG1);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[4]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
      /* rounds 4-7 */
      MSG1 = vsha256su0q_u32(MSG1, MSG2);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[8]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
      /* rounds 8-11 */
      MSG2 = vsha256su0q_u32(MSG2, MSG3);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[12]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
      /* rounds 12-15 */
      MSG3 = vsha256su0q_u32(MSG3, MSG0);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[16]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
      /* rounds 16-19 */
      MSG0 = vsha256su0q_u32(MSG0, MSG1);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[20]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
      /* rounds 20-23 */
      MSG1 = vsha256su0q_u32(MSG1, MSG2);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[24]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
      /* rounds 24-27 */
      MSG2 = vsha256su0q_u32(MSG2, MSG3);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[28]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
      /* rounds 28-31 */
      MSG3 = vsha256su0q_u32(MSG3, MSG0);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[32]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
      /* rounds 32-35 */
      MSG0 = vsha256su0q_u32(MSG0, MSG1);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[36]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
      /* rounds 36-39 */
      MSG1 = vsha256su0q_u32(MSG1, MSG2);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[40]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
      /* rounds 40-43 */
      MSG2 = vsha256su0q_u32(MSG2, MSG3);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[44]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
      /* rounds 44-47 */
      MSG3 = vsha256su0q_u32(MSG3, MSG0);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[48]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
      /* rounds 48-51 */
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[52]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      /* rounds 52-55 */
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[56]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      /* rounds 56-59 */
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[60]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      /* rounds 60-63 */
      TMP2 = STATE0;
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);
    data += 64;
  }
  vst1q_u32(&h[0], STATE0);
  vst1q_u32(&h[4], STATE1);
}

inline bool hardware_available() {
  static const bool ok = (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
  return ok;
}
#else
inline bool hardware_available() { return false; }
#endif

}  // namespace sha_detail
class Sha256 {
 public:
  explicit Sha256(HashBackend backend = HashBackend::kAuto) : backend_(backend) {}

  void update(const uint8_t* data, size_t len) {
    total_bytes_ += len;
    // Fill the partial block first, if any.
    if (buf_len_ > 0) {
      const size_t take = std::min(size_t{64} - buf_len_, len);
      std::memcpy(buf_ + buf_len_, data, take);
      buf_len_ += take;
      data += take;
      len -= take;
      if (buf_len_ == 64) {
        compress_blocks(buf_, 1);
        buf_len_ = 0;
      }
    }
    // Then all whole blocks in ONE call, straight from the caller's buffer.
    // Batching matters for the hardware path: it loads the 8-word state into
    // NEON registers once and keeps it there across every block, instead of
    // re-loading and storing it per block.
    if (len >= 64) {
      const size_t nblocks = len / 64;
      compress_blocks(data, nblocks);
      data += nblocks * 64;
      len -= nblocks * 64;
    }
    // Keep the tail for next time.
    if (len > 0) {
      std::memcpy(buf_, data, len);
      buf_len_ = len;
    }
  }

  void update(ByteSpan bytes) { update(bytes.data(), bytes.size()); }

  // Destructive: finishes the hash. Calling update() afterwards is a bug and is
  // not supported (the object should be reset or discarded).
  Digest32 finish() {
    // Padding (FIPS 180-4 5.1.1): append 0x80, then zeros, then the message
    // length in BITS as a 64-bit big-endian integer, so the total is a multiple
    // of 64 bytes. When the message tail is >= 56 bytes this spills into a
    // second block -- the case the 56-byte NIST vector exists to catch.
    const uint64_t bit_len = total_bytes_ * 8;
    uint8_t pad[72];
    size_t pad_len = 0;
    pad[pad_len++] = 0x80;
    while ((buf_len_ + pad_len) % 64 != 56) pad[pad_len++] = 0x00;
    for (int i = 7; i >= 0; i--) pad[pad_len++] = static_cast<uint8_t>(bit_len >> (i * 8));
    update(pad, pad_len);
    // update() bumps total_bytes_ past the real message length, which is
    // harmless: bit_len was captured before padding and is never re-read.

    Digest32 out{};
    for (int i = 0; i < 8; i++) {
      out[4 * i + 0] = static_cast<uint8_t>(h_[i] >> 24);
      out[4 * i + 1] = static_cast<uint8_t>(h_[i] >> 16);
      out[4 * i + 2] = static_cast<uint8_t>(h_[i] >> 8);
      out[4 * i + 3] = static_cast<uint8_t>(h_[i]);
    }
    return out;
  }

  void reset() {
    const HashBackend b = backend_;
    *this = Sha256(b);
  }

 private:
  void compress_blocks(const uint8_t* data, size_t nblocks) {
#if defined(__aarch64__)
    const bool use_hw = (backend_ == HashBackend::kHardware) ||
                        (backend_ == HashBackend::kAuto && sha_detail::hardware_available());
    if (use_hw) {
      sha_detail::compress_hw(h_, data, nblocks);
      return;
    }
#endif
    sha_detail::compress_scalar(h_, data, nblocks);
  }

  // FIPS 180-4 5.3.3 -- initial hash value: fractional parts of the square roots
  // of the first 8 primes.
  uint32_t h_[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint8_t buf_[64] = {};
  size_t buf_len_ = 0;
  uint64_t total_bytes_ = 0;
  HashBackend backend_ = HashBackend::kAuto;
};

// One-shot convenience. Identical result to the incremental form -- a property
// the test suite checks with randomized split points, because "streaming and
// one-shot disagree" is the classic hash bug and it would only surface on files
// larger than one read buffer.
inline Digest32 sha256(ByteSpan data, HashBackend backend = HashBackend::kAuto) {
  Sha256 s(backend);
  s.update(data);
  return s.finish();
}

// True when this CPU has the ARMv8 SHA-2 extension. Production code never needs
// to ask -- kAuto handles it -- but tests and benchmarks do.
inline bool sha256_has_hardware() { return sha_detail::hardware_available(); }

}  // namespace wanrep
