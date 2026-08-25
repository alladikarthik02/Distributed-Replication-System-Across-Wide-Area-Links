// LEB128 unsigned varints -- the number encoding used by the manifest (SPEC 3.3) and
// by the run-length need-set (needset.h).
//
// WHY A VARINT AND NOT A FIXED-WIDTH FIELD:
//   The two things we count are chunk indices and run lengths. Both are dominated by
//   small values -- a mostly-unchanged tree needs a handful of chunks out of millions,
//   so almost every gap and every run length fits in one or two bytes. A fixed uint64
//   would cost 8 bytes for a value of 3, and SPEC 8.3 already records that on a
//   nearly-unchanged tree the *metadata* is the dominant cost. Shrinking the metadata
//   is therefore not a micro-optimization here; it is the thing being optimized.
//
// WHY LEB128 AND NOT SQLite-STYLE OR PREFIX-LENGTH VARINTS:
//   LEB128's decoder is a three-line loop with one branch per byte and no lookup table,
//   which matters because the decoder is the side that runs on bytes a hostile peer
//   chose (SPEC S12). Fancier encodings buy a fraction of a byte on large values and
//   cost a decoder that is harder to prove bounds-safe by reading it.
//
// WHY OVER-LONG ENCODINGS ARE REJECTED (this is the part that is a security property,
// not pedantry):
//   Plain LEB128 lets the same number be spelled many ways -- 0 is `00`, but also
//   `80 00`, `80 80 00`, and so on. Two spellings of one value is how a parser and a
//   validator end up disagreeing: anything that compares, digests, or de-duplicates an
//   encoded structure (the manifest digest in SPEC 3.2's SESSION_START is exactly such
//   a thing) can be made to see two different byte strings that decode to the same
//   meaning. So the decoder demands the canonical spelling: at most 10 bytes, the final
//   byte non-zero unless the whole encoding is the single byte 0x00, and the 10th byte
//   carrying no bits above 2^64. One number, one encoding.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "wanrep/types.h"

namespace wanrep {

// 64 value bits at 7 bits per byte needs ceil(64/7) = 10 bytes. Nothing legal is longer,
// so a decoder that has consumed 10 continuation bytes is looking at an attack or at
// garbage, and either way it stops.
inline constexpr size_t kMaxVarintBytes = 10;

// Number of bytes put_varint() will emit for v. Kept next to put_varint() so the two
// cannot drift: callers size buffers with this and then trust the write.
inline size_t varint_size(uint64_t v) {
  size_t n = 1;
  while (v >= 0x80) {
    v >>= 7;
    n++;
  }
  return n;
}

inline void put_varint(std::vector<uint8_t>& out, uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<uint8_t>(v) | 0x80u);  // continuation bit set
    v >>= 7;
  }
  out.push_back(static_cast<uint8_t>(v));
}

// Returns false on truncation or on a malformed (over-long / non-canonical) encoding.
// `pos` advances ONLY on success -- a caller in a decode loop can therefore treat a
// false return as "stop, the buffer is bad" without having to remember to unwind, which
// is the kind of bookkeeping that produces off-by-one reads on hostile input.
inline bool get_varint(ByteSpan in, size_t& pos, uint64_t& out) {
  uint64_t acc = 0;
  size_t i = pos;
  for (size_t idx = 0; idx < kMaxVarintBytes; idx++) {
    if (i >= in.size()) return false;  // truncated: the buffer ended mid-number
    const uint8_t b = in[i++];
    if (idx == kMaxVarintBytes - 1 && b > 0x01) {
      // Bytes 0..8 already carry 63 value bits, so the 10th byte may contribute exactly
      // one: bit 63. Any larger value would either overflow uint64 or set a continuation
      // bit on a number that cannot legally continue.
      return false;
    }
    acc |= static_cast<uint64_t>(b & 0x7fu) << (7 * idx);
    if ((b & 0x80u) == 0) {
      // Canonical-spelling check. A terminating byte of 0x00 contributes nothing, so a
      // multi-byte encoding ending in 0x00 is padded -- the same number spelled longer.
      if (idx > 0 && b == 0) return false;
      pos = i;
      out = acc;
      return true;
    }
  }
  // Unreachable in practice: the byte at idx 9 is forced to be <= 0x01 above, which has
  // no continuation bit, so the loop always returns from inside. Kept so that a future
  // edit to kMaxVarintBytes fails closed rather than falling off the end.
  return false;
}

}  // namespace wanrep
