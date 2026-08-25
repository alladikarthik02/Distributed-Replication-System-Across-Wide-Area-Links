// In-transit compression (SPEC 3.4): an LZ4-style block codec, written in-tree.
//
// WHY IN-TREE AND NOT ZLIB:
//   Same rule as the rest of this project -- no hidden dependencies -- but here there is
//   a second, sharper reason. `decompress()` is the ONLY function in this codebase that
//   runs on attacker-controlled bytes with a pointer and a length taken from those same
//   bytes. The LZ77 decoder family is a well-known CVE farm ("copy 64 KB from 60 KB
//   back" runs off both ends of the buffer if you believe it). A decoder we wrote is a
//   decoder we can fuzz, prove bounds-safe, and explain line by line; a decoder we
//   linked is one we can only hope about.
//
// WHY THROUGHPUT AND NOT RATIO IS THE DESIGN POINT:
//   The compressor sits between the pipeline and the socket (SPEC 3.6). If it runs
//   slower than the link, it is not a bandwidth reduction -- it is a bandwidth
//   reduction that COSTS bandwidth, because the link idles while we think. A 100 Mbit/s
//   WAN is 12.5 MB/s, so the bar is "hundreds of MB/s with room to spare", not "the best
//   ratio achievable". That decides every trade-off below:
//     * one hash probe per position, no chain, no lazy matching, no optimal parse;
//     * a 64 K-entry table over 4-byte sequences -- 256 KiB, fits comfortably in L2;
//     * no entropy-coding stage at all (that is where zlib spends most of its time);
//     * a miss-streak skip so incompressible input is skimmed instead of scanned.
//   REJECTED: a Huffman/ANS back end (roughly +25% ratio for roughly -60% speed, and it
//   doubles the decoder's attack surface); chained hash buckets (better ratio, but the
//   probe loop is a cache-miss chain and this is the hot path); Rabin-style long-range
//   matching (that job is already done, better, by content-defined chunking upstream).
//
// FORMAT (LZ4 block format, deliberately -- an already-attacked design beats a novel
// one, and it means a hexdump is readable against published documentation):
//
//   sequence := token
//               [255-extension bytes for the literal length]
//               literal bytes
//               2-byte little-endian match offset      <- absent on the LAST sequence
//               [255-extension bytes for the match length]
//
//   token: high nibble = literal length (15 => extended)
//          low  nibble = match length MINUS 4 (15 => extended). The bias exists because
//                        a match shorter than 4 bytes costs more to encode than to copy.
//
//   A block ALWAYS ends with a literal run, and the last kLastLiterals bytes of the
//   input are never part of a match. That single structural rule is what lets the
//   decoder recognise the end of a block by input exhaustion, with no length prefix and
//   no terminator byte to disagree about. (The frame header already carries `raw_len`
//   and `wire_len` -- SPEC 3.2 -- so a redundant length inside the block would be a
//   second source of truth, i.e. a bug waiting to happen.)
//
// THE THREE RULES THAT ARE SAFETY REQUIREMENTS, NOT OPTIMIZATIONS (SPEC S14):
//
//   1. NEVER EXPAND. `compress()` returns 0 rather than emitting a block that is not
//      smaller than its input, and the caller then sends the batch raw with
//      kFlagCompressed clear. Without this, already-compressed media and encrypted
//      files make the "bandwidth reduction" NEGATIVE. It is enforced structurally here:
//      the output budget is min(dst_cap, n-1), so the encoder physically cannot write a
//      block that ties or expands -- it runs out of budget and gives up. One check,
//      two guarantees.
//
//   2. THE DECODER VALIDATES EVERY INSTRUCTION BEFORE EXECUTING IT. Literal length must
//      fit the remaining input AND the remaining output; match offset must be >= 1 and
//      <= bytes already produced; match length must fit the remaining output. A
//      violation is an error return -- never a truncated copy, never a clamp, never UB.
//      Beyond that the decoder rejects every structural shape the encoder cannot
//      produce (a block not ending in a literal run, a terminal token that claims a
//      match). Accepting only what we emit keeps the reachable state space as small as
//      the format allows.
//
//   3. OVERLAPPING MATCHES ARE LEGAL AND LOAD-BEARING. offset < match_len means the copy
//      reads bytes it is itself still producing -- that is how run-length encoding falls
//      out of LZ77 ("abababab" is offset 2, length 6). They MUST be copied byte-by-byte
//      forward. `memcpy` on overlapping ranges is UB, and in practice it produces
//      plausible-looking WRONG bytes on exactly the repetitive data this project exists
//      to move. tests/test_compress.cpp attacks this case directly.
#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "wanrep/result.h"
#include "wanrep/types.h"

namespace wanrep::lz {

// --------------------------------------------------------------------------------
// Format constants
// --------------------------------------------------------------------------------

// The minimum match length. Below 4 bytes a match costs more to encode (token + 2-byte
// offset = 3 bytes minimum) than the literals it replaces, so shorter matches are
// worse than useless -- they are expansion. The token's low nibble is biased by this.
inline constexpr size_t kMinMatch = 4;

// The tail of the input that is always emitted as literals. Its job here is structural,
// not performance: it guarantees the final sequence is a literal run, which is the
// decoder's end-of-block signal. 5 is the LZ4 value, kept so the format stays readable
// against the published spec.
inline constexpr size_t kLastLiterals = 5;

// The match window. Fixed by the format: the offset field is 2 bytes, so nothing further
// back than 65535 can be referenced. This is why SPEC 3.4's batch-size curve flattens --
// batching beyond ~64 KiB cannot widen the dictionary, it can only amortize the token
// overhead. bench/bench_lz.cpp measures exactly that and says so.
inline constexpr uint32_t kMaxOffset = 65535;

// 2^16 entries x 4 bytes = 256 KiB. Sized to sit in L2 rather than L1: the table is
// touched once per input position and is pure random access, so what matters is that a
// probe is not a trip to DRAM. Larger tables measurably improve ratio on multi-megabyte
// inputs and measurably hurt throughput; our inputs are batches bounded by kMaxFrame
// (1 MiB), where 64 K entries already covers the whole 64 KiB match window many times
// over.
inline constexpr unsigned kHashBits = 16;
inline constexpr size_t kHashSize = size_t{1} << kHashBits;

// How fast the search step grows during a run of failed probes: after N consecutive
// misses the step is 1 + N/64. On compressible data a match resets the streak almost
// immediately, so this is invisible; on incompressible data it turns an O(n) scan into
// an O(sqrt(n))-probe skim, which is what makes rule 1's "give up" path cheap.
inline constexpr unsigned kSkipLog = 6;

// Inputs above this are refused (compress() returns 0 -> the caller sends raw). The
// encoder addresses positions in 32 bits (see HashTable below), and 1 GiB is three
// orders of magnitude above kMaxFrame, so this can only ever fire on misuse -- and when
// it does, it degrades to "send it uncompressed", never to a wrong answer.
inline constexpr size_t kMaxInput = size_t{1} << 30;

// --------------------------------------------------------------------------------
// Internals
// --------------------------------------------------------------------------------

namespace detail {

// SPEC 2.5 measured this platform as little-endian, and count_match() below depends on
// it for the "first differing byte = lowest set bit" trick. Asserted rather than
// assumed, because on a big-endian host that trick returns a wrong match length and the
// compressor would emit a block that decodes to different bytes -- silent corruption,
// not a crash.
static_assert(std::endian::native == std::endian::little,
              "count_match's bit trick assumes little-endian (SPEC 2.5)");

inline uint32_t read32(const uint8_t* p) {
  uint32_t v;
  std::memcpy(&v, p, 4);
  return v;
}

inline uint64_t read64(const uint8_t* p) {
  uint64_t v;
  std::memcpy(&v, p, 8);
  return v;
}

// Fibonacci hashing: multiply by 2^32/phi and keep the HIGH bits. The high bits of a
// multiply mix contributions from every input byte, which the low bits do not -- taking
// `seq % kHashSize` instead would bucket purely on the first two bytes and collapse the
// table on structured data (think record headers that share a 2-byte tag).
inline uint32_t hash4(uint32_t seq) {
  return (seq * 2654435761u) >> (32 - kHashBits);
}

// Number of leading bytes on which a and b agree, capped at `max`.
inline size_t count_match(const uint8_t* a, const uint8_t* b, size_t max) {
  size_t i = 0;
  while (i + 8 <= max) {
    const uint64_t x = read64(a + i) ^ read64(b + i);
    if (x != 0) {
      // Little-endian: byte k of the word sits in bits [8k, 8k+8), so the lowest set
      // bit of the XOR names the first byte that differs.
      return i + (static_cast<size_t>(std::countr_zero(x)) >> 3);
    }
    i += 8;
  }
  while (i < max && a[i] == b[i]) i++;
  return i;
}

// The match-finding hash table.
//
// WHY IT IS NOT CLEARED PER CALL, AND WHY THAT IS STILL DETERMINISTIC:
//   Zeroing 256 KiB costs more than compressing an 8 KiB batch, which would make the
//   small-batch end of SPEC 3.4's batch-size curve a measurement of memset instead of a
//   measurement of compression. So the table persists -- but a persisting table would
//   normally make compress() history-dependent, and a "pure" function whose output
//   depends on what the thread did earlier is a trap for anyone diffing two runs.
//
//   The fix is arithmetic rather than bookkeeping. Entries store an ABSOLUTE position
//   `base + i`, and each call advances `base` past the previous call's positions by
//   more than kMaxOffset. Every entry left over from an earlier call is therefore more
//   than 65535 behind every position in this call, so it fails the distance check that
//   the format requires anyway -- unconditionally, on every input. A stale entry cannot
//   change the output; it can only cost the one comparison that rejects it.
//   Consequence: compress() is a pure function of its input, and a fresh table and a
//   dirty one produce byte-identical blocks. tests/test_compress.cpp asserts that.
//
//   The same arithmetic subsumes the empty-entry case: a zeroed entry is 0, `base`
//   starts above kMaxOffset, so "never written" and "written long ago" are rejected by
//   one comparison instead of a sentinel value and a branch.
//
// Thread-local because SPEC 3.6 runs M compressor threads. Sharing one table between
// them would be a data race whose symptom is a worse ratio -- i.e. a race that no
// assertion would ever catch. TSan would, but only if it ran on a build that happened
// to contend.
struct HashTable {
  std::array<uint32_t, kHashSize> slots{};
  uint32_t base = kMaxOffset + 1;

  // Claims the position range for one call and returns its base.
  uint32_t reserve(size_t n) {
    if (uint64_t{base} + n + kMaxOffset + 1 > 0xFFFFFFFFull) {
      // ~4 GiB compressed on this thread. The counter cannot advance without breaking
      // the staleness invariant above, so the table is genuinely cleared and restarted.
      slots.fill(0);
      base = kMaxOffset + 1;
    }
    const uint32_t b = base;
    base = static_cast<uint32_t>(uint64_t{b} + n + kMaxOffset + 1);
    return b;
  }
};

inline HashTable& thread_table() {
  static thread_local HashTable t;
  return t;
}

}  // namespace detail

// --------------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------------

// Worst-case size of a compressed block, for callers sizing a scratch buffer.
//
// The worst case is "no match anywhere": one token per 255 literals, plus the literal
// bytes themselves. Note that compress() never actually emits a block this large -- it
// gives up and returns 0 long before (rule 1) -- so this bound exists to size a buffer,
// never to size a frame.
inline size_t max_compressed_size(size_t n) {
  return n + n / 255 + 16;
}

// Compresses `src` into `dst`. Returns the number of bytes written, or 0 to mean "this
// does not compress -- send it raw" (SPEC S14 rule 1).
//
// Never writes past dst_cap, and never writes as many as src.size() bytes: both follow
// from the single `budget` below.
inline size_t compress(ByteSpan src, uint8_t* dst, size_t dst_cap) {
  const size_t n = src.size();
  if (n > kMaxInput) return 0;

  // Too short to hold a single legal match: the first match may start no earlier than
  // position 1 (it needs an earlier candidate) and must end kLastLiterals bytes before
  // the end. Anything shorter can only be encoded as literals, which is always larger
  // than the input, so the answer is already known.
  if (n < 1 + kMinMatch + kLastLiterals) return 0;

  // THE budget. min(dst_cap, n-1) enforces "never overflow the caller's buffer" and
  // "never expand" with the same comparison, and it doubles as an early-out: on
  // incompressible input the encoder hits the budget and returns 0 without having to
  // finish the block.
  const size_t budget = (dst_cap < n - 1) ? dst_cap : n - 1;

  const uint8_t* const s = src.data();
  size_t op = 0;

  // Emits one sequence. `match_len == 0` means the final, literal-only sequence.
  // Returns false when the budget is exhausted, which the caller turns into "this block
  // does not compress" -- never into a truncated block.
  auto emit = [&](size_t lit_len, size_t lit_at, uint32_t offset, size_t match_len) {
    const size_t lit_ext = lit_len >= 15 ? (lit_len - 15) / 255 + 1 : 0;
    const size_t mtok = match_len != 0 ? match_len - kMinMatch : 0;
    const size_t m_ext = (match_len != 0 && mtok >= 15) ? (mtok - 15) / 255 + 1 : 0;
    const size_t need = 1 + lit_ext + lit_len + (match_len != 0 ? 2 + m_ext : 0);
    if (need > budget - op) return false;

    const size_t token_at = op++;
    dst[token_at] = static_cast<uint8_t>((lit_len >= 15 ? 15u : lit_len) << 4);
    if (lit_len >= 15) {
      size_t rest = lit_len - 15;
      for (; rest >= 255; rest -= 255) dst[op++] = 255;
      dst[op++] = static_cast<uint8_t>(rest);
    }
    if (lit_len != 0) std::memcpy(dst + op, s + lit_at, lit_len);
    op += lit_len;

    if (match_len != 0) {
      dst[token_at] |= static_cast<uint8_t>(mtok >= 15 ? 15u : mtok);
      dst[op++] = static_cast<uint8_t>(offset & 0xff);
      dst[op++] = static_cast<uint8_t>(offset >> 8);
      if (mtok >= 15) {
        size_t rest = mtok - 15;
        for (; rest >= 255; rest -= 255) dst[op++] = 255;
        dst[op++] = static_cast<uint8_t>(rest);
      }
    }
    return true;
  };

  detail::HashTable& ht = detail::thread_table();
  const uint32_t base = ht.reserve(n);

  const size_t matchlimit = n - kLastLiterals;             // a match may not extend past this
  const size_t search_end = matchlimit - kMinMatch + 1;    // nor start at or after this
  size_t anchor = 0;                                       // start of the pending literal run
  size_t ip = 1;                                           // a match needs a strictly earlier candidate
  uint32_t miss = 0;                                       // consecutive failed probes

  ht.slots[detail::hash4(detail::read32(s))] = base;

  while (ip < search_end) {
    const uint32_t seq = detail::read32(s + ip);
    const uint32_t h = detail::hash4(seq);
    const uint32_t cand = ht.slots[h];
    const uint32_t cur = base + static_cast<uint32_t>(ip);
    ht.slots[h] = cur;

    // Three ways to reject a candidate, cheapest first. `cand < base` can only be true
    // for a leftover from an earlier call, which the reserve() arithmetic already makes
    // unreachable via the distance test -- it is checked anyway because the very next
    // line does pointer arithmetic with `cand - base`, and a memory-safety property
    // should not rest on an invariant proved three screens away.
    if (cand < base || cur - cand > kMaxOffset) {
      ip += 1 + (miss++ >> kSkipLog);
      continue;
    }
    const size_t mpos = static_cast<size_t>(cand - base);  // < ip, so in bounds
    if (detail::read32(s + mpos) != seq) {
      ip += 1 + (miss++ >> kSkipLog);
      continue;
    }

    // Extend the match BACKWARDS over bytes already committed to the literal run. This
    // is free ratio -- one comparison per byte gained -- and it matters more than it
    // looks: the hash finds the match at a 4-byte-aligned-by-luck position, and on
    // structured data the true match usually started several bytes earlier.
    size_t xp = ip, mp = mpos;
    while (xp > anchor && mp > 0 && s[xp - 1] == s[mp - 1]) {
      xp--;
      mp--;
    }

    const size_t from = xp + kMinMatch;
    const size_t match_len =
        kMinMatch + detail::count_match(s + from, s + mp + kMinMatch, matchlimit - from);

    if (!emit(xp - anchor, anchor, static_cast<uint32_t>(xp - mp), match_len)) return 0;

    anchor = xp + match_len;
    ip = anchor;
    miss = 0;

    // Seed the table with the position two bytes before the new anchor. One store, and
    // it catches the common case where the next match begins where this one ended --
    // without it, single-probe matching loses the run entirely on data whose period is
    // shorter than the match it just emitted.
    if (anchor >= 2 && anchor + kMinMatch <= n) {
      const size_t back = anchor - 2;
      ht.slots[detail::hash4(detail::read32(s + back))] = base + static_cast<uint32_t>(back);
    }
  }

  // The tail. Always a literal run, and always at least kLastLiterals bytes of one --
  // that is the decoder's end-of-block signal (see the format note in the file header).
  if (!emit(n - anchor, anchor, 0, 0)) return 0;
  return op;
}

// Decompresses `src` into `dst`. Returns the number of bytes produced.
//
// This is the function that runs on bytes a hostile peer chose. It makes exactly two
// promises, and tests/test_compress.cpp attacks both: it never reads or writes outside
// `src` and `dst[0, dst_cap)` for ANY input, and it never produces more than dst_cap
// bytes. Everything else is an error return. SPEC S14.
inline Result<size_t> decompress(ByteSpan src, uint8_t* dst, size_t dst_cap) {
  const uint8_t* const in = src.data();
  const size_t in_n = src.size();
  size_t ip = 0;   // read cursor: invariant ip <= in_n
  size_t op = 0;   // write cursor: invariant op <= dst_cap
  bool ended_with_literals = false;

  while (ip < in_n) {
    const uint8_t token = in[ip++];

    // ---- literal length ---------------------------------------------------------
    // uint64_t, not size_t, so the accumulation below has one documented width no
    // matter the platform. It cannot run away: each extension byte adds at most 255 and
    // consumes an input byte, and the bound check inside the loop stops it long before
    // the arithmetic could matter.
    uint64_t lit = token >> 4;
    if (lit == 15) {
      for (;;) {
        if (ip >= in_n) return err(Err::kMalformed, "literal-length extension runs off the block");
        const uint8_t b = in[ip++];
        lit += b;
        // A literal run can never be longer than the entire block that encodes it.
        // Checking here rather than after the loop turns a crafted 10-byte block
        // claiming a 4 GiB literal run into an immediate error instead of a long walk.
        if (lit > in_n) return err(Err::kMalformed, "literal length exceeds the block size");
        if (b != 255) break;
      }
    }
    if (lit > in_n - ip) return err(Err::kMalformed, "literal run exceeds the remaining input");
    if (lit > dst_cap - op) return err(Err::kTooLarge, "literal run exceeds the output capacity");
    if (lit != 0) std::memcpy(dst + op, in + ip, static_cast<size_t>(lit));
    op += static_cast<size_t>(lit);
    ip += static_cast<size_t>(lit);

    // ---- end of block -----------------------------------------------------------
    // Every block our encoder emits ends with a literal run, so input exhaustion here
    // is the terminator. The low nibble must be zero: a terminal token that claims a
    // match is a shape the encoder cannot produce, and accepting it would mean silently
    // ignoring a field an attacker controls.
    if (ip == in_n) {
      if ((token & 0x0f) != 0) return err(Err::kMalformed, "final token declares a match");
      ended_with_literals = true;
      break;
    }

    // ---- match offset -----------------------------------------------------------
    if (in_n - ip < 2) return err(Err::kMalformed, "truncated match offset");
    const uint32_t offset =
        static_cast<uint32_t>(in[ip]) | (static_cast<uint32_t>(in[ip + 1]) << 8);
    ip += 2;
    // offset 0 would be "copy from where I am about to write" -- an infinite self-
    // reference, and in a careless decoder a read of uninitialised memory.
    if (offset == 0) return err(Err::kMalformed, "match offset is zero");
    // The one check that stops the classic overflow: the source of the copy must lie
    // inside what we have ALREADY produced, not merely inside the buffer. `> op`, not
    // `> dst_cap`.
    if (offset > op) return err(Err::kMalformed, "match offset reaches before the output start");

    // ---- match length -----------------------------------------------------------
    uint64_t mlen = token & 0x0f;
    if (mlen == 15) {
      for (;;) {
        if (ip >= in_n) return err(Err::kMalformed, "match-length extension runs off the block");
        const uint8_t b = in[ip++];
        mlen += b;
        if (mlen > dst_cap) return err(Err::kTooLarge, "match length exceeds the output capacity");
        if (b != 255) break;
      }
    }
    mlen += kMinMatch;
    if (mlen > dst_cap - op) return err(Err::kTooLarge, "match length exceeds the output capacity");

    const size_t len = static_cast<size_t>(mlen);
    if (offset >= len) {
      // Disjoint: the source range ends at or before dst+op, which is where the
      // destination begins. memcpy is legal here and this is the common case.
      std::memcpy(dst + op, dst + op - offset, len);
    } else {
      // OVERLAPPING MATCH. Legal, intentional, and the whole reason LZ77 encodes runs
      // for free: offset 1 length 200 means "the previous byte, 200 more times".
      // memcpy would be UB and memmove would be WRONG -- memmove copies the ORIGINAL
      // source bytes, whereas the format requires each output byte to be visible to the
      // bytes produced after it. Forward, one byte at a time, on purpose (SPEC S14).
      for (size_t i = 0; i < len; i++) dst[op + i] = dst[op + i - offset];
    }
    op += len;
  }

  // Falling out of the loop without the terminal literal run means the block ended
  // after a match (or was empty). Neither shape is producible by compress(), so it is
  // rejected rather than silently accepted with a plausible-looking output length.
  if (!ended_with_literals) return err(Err::kMalformed, "block does not end with a literal run");
  return op;
}

}  // namespace wanrep::lz
