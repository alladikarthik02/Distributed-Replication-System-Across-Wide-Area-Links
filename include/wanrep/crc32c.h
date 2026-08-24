// PROVENANCE: carried over from project #1 (`dedupe`), commit ac2096a, with the
// namespace and include prefix renamed and nothing else changed. This file is pure,
// dependency-free, already verified against published vectors, and already does runtime
// hardware dispatch -- rewriting it here would produce a second implementation to keep
// correct, not a second piece of learning. Its test suite is carried over with it, so
// the guarantee travels with the code. SPEC 0 records the carry-over.
//
// CRC32C (Castagnoli, polynomial 0x1EDC6F41 / reflected 0x82F63B78).
//
// WHY A CRC AT ALL WHEN WE ALREADY HAVE SHA-256:
//   They answer different questions.
//     SHA-256 answers "WHICH chunk is this?"    -- identity, content addressing.
//     CRC32C  answers "is this record INTACT?"  -- integrity of stored bytes.
//   Every chunk read verifies its CRC. Doing that with SHA-256 instead would cost
//   ~10x more CPU on the restore path for no extra safety against the thing a CRC
//   is for: torn writes and bit rot. The recovery scan (SPEC 3.3) also needs an
//   integrity check it can apply to a record it does NOT yet trust the fingerprint
//   of -- a self-check, which is exactly what a CRC is.
//
// WHY CASTAGNOLI (CRC32C) AND NOT THE ETHERNET/zlib CRC32:
//   Better error-detection properties at our record sizes, and -- decisively --
//   it is the polynomial implemented in hardware by both x86 (SSE4.2 crc32) and
//   ARMv8 (crc32c* instructions). Choosing the other polynomial would forfeit a
//   ~10x speedup on the hot path for no benefit.
//
// THREE IMPLEMENTATIONS, ONE ANSWER:
//   bitwise  -- the definition, straight from the polynomial. Slow, obviously
//               correct, and used as the differential-test oracle.
//   table    -- slicing-by-8, the portable production path.
//   hardware -- ARMv8 crc32c instructions, selected at RUNTIME.
//   All three MUST agree bit-for-bit: a store written on a CRC-capable machine has
//   to verify on one without, or we have invented a portability data-loss bug.
//   tests/test_crc32c.cpp proves the agreement over randomized inputs.
//
// WHY RUNTIME DISPATCH AND NOT -march=armv8-a+crc:
//   Measured in the container (T1 probe): __ARM_FEATURE_CRC32 is NOT defined at
//   Ubuntu's default -march, yet AT_HWCAP says the CPU has the instructions.
//   Compiling the whole binary with +crc would produce an executable that dies
//   with SIGILL on any machine lacking them. Runtime dispatch keeps one portable
//   binary and still gets the fast path.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "wanrep/types.h"

#if defined(__aarch64__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace wanrep {
namespace crc_detail {

inline constexpr uint32_t kPolyReflected = 0x82F63B78u;

// --- 1. The definition -------------------------------------------------------
// Reflected CRC: bits enter at the bottom, the register shifts right.
inline uint32_t bitwise(uint32_t crc, const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (int k = 0; k < 8; k++) {
      // Branchless conditional XOR: -(crc & 1) is all-ones when the low bit is
      // set, all-zeros otherwise.
      crc = (crc >> 1) ^ (kPolyReflected & (~(crc & 1) + 1));
    }
  }
  return crc;
}

// --- 2. Slicing-by-8 tables, built at COMPILE time ---------------------------
// 8 x 256 x 4B = 8 KiB of .rodata, and zero startup cost. Table[0] is the
// classic byte-at-a-time table; Table[k] folds in k extra trailing zero bytes,
// which is what lets us consume 8 bytes per iteration.
struct Tables {
  uint32_t t[8][256] = {};
};

inline constexpr Tables make_tables() {
  Tables tab{};
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (kPolyReflected & (~(c & 1) + 1));
    tab.t[0][i] = c;
  }
  for (uint32_t i = 0; i < 256; i++) {
    for (int k = 1; k < 8; k++) {
      const uint32_t prev = tab.t[k - 1][i];
      tab.t[k][i] = (prev >> 8) ^ tab.t[0][prev & 0xFF];
    }
  }
  return tab;
}

inline constexpr Tables kTables = make_tables();

inline uint32_t table(uint32_t crc, const uint8_t* p, size_t n) {
  // Eight bytes per iteration: eight independent table lookups that the CPU can
  // issue in parallel, instead of an 8-deep dependency chain of one lookup each.
  while (n >= 8) {
    uint32_t lo, hi;
    std::memcpy(&lo, p, 4);      // little-endian host (asserted in T0)
    std::memcpy(&hi, p + 4, 4);
    lo ^= crc;
    crc = kTables.t[7][lo & 0xFF] ^ kTables.t[6][(lo >> 8) & 0xFF] ^
          kTables.t[5][(lo >> 16) & 0xFF] ^ kTables.t[4][(lo >> 24) & 0xFF] ^
          kTables.t[3][hi & 0xFF] ^ kTables.t[2][(hi >> 8) & 0xFF] ^
          kTables.t[1][(hi >> 16) & 0xFF] ^ kTables.t[0][(hi >> 24) & 0xFF];
    p += 8;
    n -= 8;
  }
  while (n--) crc = (crc >> 8) ^ kTables.t[0][(crc ^ *p++) & 0xFF];
  return crc;
}

// --- 3. Hardware path (ARMv8 CRC32 extension) --------------------------------
#if defined(__aarch64__)
// The target attribute lets THIS FUNCTION ONLY be compiled with the +crc
// feature, while the rest of the translation unit stays baseline armv8-a.
__attribute__((target("+crc"))) inline uint32_t hardware(uint32_t crc, const uint8_t* p,
                                                         size_t n) {
  while (n >= 8) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    crc = __builtin_aarch64_crc32cx(crc, v);
    p += 8;
    n -= 8;
  }
  if (n >= 4) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    crc = __builtin_aarch64_crc32cw(crc, v);
    p += 4;
    n -= 4;
  }
  if (n >= 2) {
    uint16_t v;
    std::memcpy(&v, p, 2);
    crc = __builtin_aarch64_crc32ch(crc, v);
    p += 2;
    n -= 2;
  }
  if (n) crc = __builtin_aarch64_crc32cb(crc, *p);
  return crc;
}

inline bool hardware_available() {
  static const bool ok = (getauxval(AT_HWCAP) & HWCAP_CRC32) != 0;
  return ok;
}
#else
inline bool hardware_available() { return false; }
#endif

}  // namespace crc_detail

// Public API.
//
// `prev` allows chaining: crc32c(b, crc32c(a)) == crc32c(a ++ b). That identity
// is a test, not a comment -- it is what lets a chunk's CRC be computed while
// streaming without buffering the whole chunk.
inline uint32_t crc32c(ByteSpan data, uint32_t prev = 0) {
  uint32_t crc = ~prev;  // pre-invert; standard CRC32 framing
#if defined(__aarch64__)
  if (crc_detail::hardware_available()) {
    crc = crc_detail::hardware(crc, data.data(), data.size());
  } else {
    crc = crc_detail::table(crc, data.data(), data.size());
  }
#else
  crc = crc_detail::table(crc, data.data(), data.size());
#endif
  return ~crc;  // post-invert
}

// Explicit-implementation entry points, for the differential tests and the
// benchmark. Production code calls crc32c() and lets dispatch decide.
inline uint32_t crc32c_bitwise(ByteSpan d, uint32_t prev = 0) {
  return ~crc_detail::bitwise(~prev, d.data(), d.size());
}
inline uint32_t crc32c_table(ByteSpan d, uint32_t prev = 0) {
  return ~crc_detail::table(~prev, d.data(), d.size());
}
inline bool crc32c_has_hardware() { return crc_detail::hardware_available(); }
#if defined(__aarch64__)
inline uint32_t crc32c_hardware(ByteSpan d, uint32_t prev = 0) {
  return ~crc_detail::hardware(~prev, d.data(), d.size());
}
#endif

}  // namespace wanrep
