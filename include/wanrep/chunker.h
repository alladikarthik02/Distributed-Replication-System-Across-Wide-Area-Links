// Content-defined chunking: FastCDC with a Gear rolling hash.
//
// WHY CONTENT-DEFINED AND NOT FIXED-SIZE (this is the whole reason the project works):
//   Split a file into fixed 8 KiB blocks, then insert one byte at the front. Every
//   subsequent block's content shifts by one, every fingerprint changes, and the target
//   needs all of them -- a one-byte edit costs a full transfer. This is the
//   "boundary-shift problem", and it is why chunk boundaries must be chosen by the
//   *content* rather than by the offset. A rolling hash over a sliding window cuts
//   wherever the hash matches a mask; an insertion perturbs only the chunks near it and
//   boundaries re-synchronize downstream. tests/test_chunker.cpp measures exactly this,
//   with a fixed-size chunker as the control (SPEC R1.1).
//
// WHY GEAR AND NOT RABIN:
//   Rabin fingerprinting needs a 48-byte explicit window, a multiply and a modulo per
//   byte, plus a slide-out table. Gear is `h = (h << 1) + GEAR[byte]`: one shift, one
//   add, one table lookup. The window is implicit -- after 64 shifts a byte's
//   contribution has fallen off the top of the 64-bit word, so the window is "the last
//   ~64 bytes" for free, with no bookkeeping.
//
// WHAT FastCDC ADDS OVER PLAIN GEAR (both implemented here):
//   * Normalized chunking (NC level 2): a STRICTER mask before the average size (harder
//     to cut) and a LOOSER mask after (easier to cut). This pulls the chunk-size
//     distribution in around the target, which cuts both tiny chunks (whose per-chunk
//     overhead dominates) and giant chunks (which dedup poorly). Measured in T1.
//   * Cut-point skipping: never even test for a cut inside the first MinSize bytes.
//     Sub-minimum chunks are pure overhead, so testing for them is wasted work in the
//     hot loop.
//
// DETERMINISM IS A PROTOCOL REQUIREMENT, NOT A NICETY:
//   The same bytes must produce the same boundaries on every run, on every machine, and
//   whether the data arrives in one buffer or in a thousand reads. If they don't, the
//   fingerprints differ, the set difference in SPEC 3.3 finds nothing in common, and
//   "send only changed chunks" degenerates into "send everything". Hence: a Gear table
//   generated from a fixed documented seed, no floating point, no platform-dependent
//   types, and a test that feeds the same input in randomly-sized pieces and demands
//   byte-identical boundaries.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "wanrep/types.h"

namespace wanrep {

namespace chunk_detail {

// The Gear table: 256 pseudo-random 64-bit values, one per byte value.
//
// Generated at compile time by splitmix64 from a fixed seed rather than pasted in as a
// literal table. Two reasons: a 256-entry literal table is 256 opportunities for a typo
// that produces a *working* chunker with subtly different boundaries (which would only
// show up as a mysteriously poor dedup ratio), and generating it makes the value
// provenance auditable in four lines instead of trusted.
//
// The seed is part of the on-wire contract: change it and every fingerprint in every
// existing store becomes unreachable. It is 2^64/phi, the standard golden-ratio
// constant -- chosen because it is a recognizable published value rather than something
// that looks like it might mean something.
inline constexpr uint64_t kGearSeed = 0x9E3779B97F4A7C15ull;

constexpr std::array<uint64_t, 256> make_gear_table() {
  std::array<uint64_t, 256> g{};
  uint64_t x = kGearSeed;
  for (size_t i = 0; i < 256; i++) {
    // splitmix64: a well-studied finalizer with good avalanche in 64 bits.
    x += kGearSeed;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    g[i] = z ^ (z >> 31);
  }
  return g;
}

inline constexpr std::array<uint64_t, 256> kGear = make_gear_table();

}  // namespace chunk_detail

// Chunking parameters. Part of the protocol handshake (SPEC 3.2): both nodes must agree
// or they compute different boundaries and share nothing.
struct ChunkParams {
  uint32_t min = kMinChunk;  // 2 KiB
  uint32_t avg = kAvgChunk;  // 8 KiB
  uint32_t max = kMaxChunk;  // 64 KiB

  // The two normalized-chunking masks. Bit counts, not the values, are what matter:
  // a mask with N bits set gives a 2^-N chance of cutting at each position, so the
  // expected run length is 2^N bytes.
  //   mask_s: 15 bits set -> expected 32 KiB, i.e. cutting is HARD below the average
  //   mask_l: 11 bits set -> expected  2 KiB, i.e. cutting is EASY above it
  // Together they concentrate the distribution around avg. The specific bit *patterns*
  // are the FastCDC paper's, spread across the word so the masked bits are not adjacent
  // (adjacent bits of a shift-based hash are strongly correlated, which would make the
  // effective mask narrower than its popcount suggests).
  uint64_t mask_s = 0x0003590703530000ull;
  uint64_t mask_l = 0x0000d90003530000ull;

  constexpr bool valid() const {
    return min > 0 && min <= avg && avg <= max && max <= kMaxChunk * 16;
  }
};

struct Chunk {
  size_t offset = 0;
  size_t length = 0;
};

class Chunker {
 public:
  explicit Chunker(ChunkParams p = {}) : p_(p) {}

  const ChunkParams& params() const { return p_; }

  // Finds the next chunk boundary in `data`, which MUST start at a chunk boundary.
  //
  // Returns the chunk length, in (0, max]. Returns 0 to mean "I need more data" --
  // which can only happen when `at_eof` is false.
  //
  // Stateless on purpose. FastCDC resets the rolling hash at every chunk boundary, so
  // there is no carry-over between chunks to keep, and a stateless function is one that
  // cannot desynchronize between the streaming caller and the batch caller. That
  // property is what tests/test_chunker.cpp's streaming-vs-batch differential relies on.
  size_t next_cut(ByteSpan data, bool at_eof) const {
    const size_t n = data.size();
    if (n == 0) return 0;

    // Not enough bytes to reach the minimum: either this is the file's short tail, or
    // we simply have not been given enough yet.
    if (n <= p_.min) return at_eof ? n : 0;

    const size_t limit = std::min<size_t>(n, p_.max);
    const size_t normal = std::min<size_t>(limit, p_.avg);

    uint64_t h = 0;
    size_t i = p_.min;  // cut-point skipping: positions below min are never candidates

    // Region 1: below the target average. Strict mask -- resist cutting here, so short
    // chunks are rare.
    for (; i < normal; i++) {
      h = (h << 1) + chunk_detail::kGear[data[i]];
      if ((h & p_.mask_s) == 0) return i + 1;
    }
    // Region 2: at or above the target average. Loose mask -- cut readily, so long
    // chunks are rare.
    for (; i < limit; i++) {
      h = (h << 1) + chunk_detail::kGear[data[i]];
      if ((h & p_.mask_l) == 0) return i + 1;
    }

    // Hit the hard ceiling without the content ever saying "cut here". Forced cut.
    // This is the case that keeps pathological input (long zero runs, highly structured
    // binaries) from producing one enormous chunk -- and it is the case whose frequency
    // T1 reports, because a high forced-cut rate means the content is defeating the
    // content-defined-ness and the dedup ratio will suffer.
    if (limit == p_.max) return p_.max;

    // Ran out of buffer before either a cut or the ceiling.
    return at_eof ? n : 0;
  }

  // Convenience for tests, benchmarks, and any caller holding the whole buffer.
  // Deliberately NOT the hot path: the source streams files rather than loading them
  // (SPEC S10), so this exists to have something to differential-test the stream against.
  std::vector<Chunk> chunk_all(ByteSpan data) const {
    std::vector<Chunk> out;
    size_t pos = 0;
    while (pos < data.size()) {
      const size_t len = next_cut(data.subspan(pos), /*at_eof=*/true);
      if (len == 0) break;  // unreachable at_eof, but never loop forever on a bug
      out.push_back({pos, len});
      pos += len;
    }
    return out;
  }

 private:
  ChunkParams p_;
};

// A fixed-size chunker. Not used in production -- it exists solely as the CONTROL for
// the boundary-shift test. Without it, "content-defined chunking preserves boundaries"
// is a claim with nothing to compare against, and a test that only ever passes tells
// you nothing about what it is measuring (SPEC R1.1).
inline std::vector<Chunk> fixed_chunk_all(ByteSpan data, size_t size) {
  std::vector<Chunk> out;
  for (size_t pos = 0; pos < data.size(); pos += size) {
    out.push_back({pos, std::min(size, data.size() - pos)});
  }
  return out;
}

}  // namespace wanrep
