// Core types and layout contracts.
//
// This header defines the *shapes* that the wire protocol (SPEC 3.2) and the target
// store (SPEC 3.5) agree on. It deliberately contains no logic: encoding lives in
// frame.h (T2) and the store lives in T6. Putting the layouts here, in T0, means the
// static_asserts below fail at the very first compile if the toolchain ever pads these
// structs differently -- rather than at T6, after code has been written on top of a
// layout that was never true.
//
// WHY NOT `#pragma pack(1)`:
//   Packing would make the layout true by force, and make every field access
//   potentially unaligned (slow on x86, a trap on some ARM configurations, and UB by
//   the standard). Instead the fields are *ordered* so that natural alignment produces
//   exactly the intended layout, and that intent is asserted. If a future edit reorders
//   a field, the assert fires. A packed struct would have silently absorbed the change.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace wanrep {

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

// A SHA-256 digest: the name of a chunk. Content addressing means this value *is*
// the identity of the bytes -- see SPEC 3.0.
using Digest32 = std::array<uint8_t, 32>;

// A hash functor for using a Digest32 as a map key. SHA-256 output is uniformly
// distributed, so the first 8 bytes are already an excellent hash -- re-hashing them
// would cost time and add nothing.
struct DigestHash {
  size_t operator()(const Digest32& d) const noexcept {
    uint64_t v;
    std::memcpy(&v, d.data(), sizeof(v));
    return static_cast<size_t>(v);
  }
};

using ByteSpan = std::span<const uint8_t>;

// Convenience for tests and CLI output. Never used on the hot path.
inline std::string to_hex(ByteSpan bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (size_t i = 0; i < bytes.size(); i++) {
    out[2 * i] = kHex[bytes[i] >> 4];
    out[2 * i + 1] = kHex[bytes[i] & 0x0f];
  }
  return out;
}

inline std::string to_hex(const Digest32& d) { return to_hex(ByteSpan(d.data(), d.size())); }

// Returns false on any malformed input rather than throwing or asserting: this parses
// text that may come from a file, a CLI flag, or a peer (SPEC S12).
inline bool from_hex(std::string_view s, Digest32& out) {
  if (s.size() != 64) return false;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < 32; i++) {
    const int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

// Helper for turning any trivially-copyable buffer into bytes.
inline ByteSpan as_bytes(const void* p, size_t n) {
  return ByteSpan(static_cast<const uint8_t*>(p), n);
}
inline ByteSpan as_bytes(std::string_view s) {
  return ByteSpan(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// ---------------------------------------------------------------------------
// Chunking parameters (SPEC 3.3 / T1)
// ---------------------------------------------------------------------------
//
// Both nodes MUST agree on these or they compute different chunk boundaries, every
// fingerprint differs, and the set difference in SPEC 3.3 degenerates to "send
// everything." They are therefore part of the protocol handshake, not a local tunable.
inline constexpr uint32_t kMinChunk = 2u * 1024;   // below this, per-chunk overhead dominates
inline constexpr uint32_t kAvgChunk = 8u * 1024;   // target average; sets manifest size and delta granularity
inline constexpr uint32_t kMaxChunk = 64u * 1024;  // bounds the worst case on pathological data

// ---------------------------------------------------------------------------
// Wire frame header (SPEC 3.2) -- 32 bytes, little-endian
// ---------------------------------------------------------------------------

enum class FrameType : uint8_t {
  kHello         = 1,   // S->T  version, capabilities, dataset
  kHelloAck      = 2,   // T->S
  kSessionStart  = 3,   // S->T  new job
  kSessionResume = 4,   // S->T  continue an interrupted job    (SPEC 3.7)
  kSessionAck    = 5,   // T->S  session id + durable high-water mark
  kManifest      = 6,   // S->T  generation manifest, streamed
  kNeed          = 7,   // T->S  RLE indices into the canonical chunk list (SPEC 3.3)
  kChunks        = 8,   // S->T  a compressed batch of chunk payloads, tagged with plan seq
  kCheckpoint    = 9,   // T->S  advisory contiguous high-water mark
  kGenCommit     = 10,  // S->T  all needed chunks sent; commit generation G
  kCommitAck     = 11,  // T->S  commit record is durable -- only now is G replicated
  kError         = 12,  // both  code + message; a node that cannot continue says so
  kBye           = 13,  // both  orderly shutdown, so read()==0 means "done" not "died"
};

// Frame flags (bitmask in FrameHeader::flags).
inline constexpr uint8_t kFlagCompressed = 1u << 0;  // payload is an LZ block (SPEC 3.4)

// 'W','R','P','1' read as a little-endian uint32. Serves two purposes: it pins the
// protocol version into every frame, and it is a recognisable eye-catcher in a hexdump
// when the framing itself is what is broken.
inline constexpr uint32_t kFrameMagic =
    (uint32_t{'W'}) | (uint32_t{'R'} << 8) | (uint32_t{'P'} << 16) | (uint32_t{'1'} << 24);

// The hard ceiling on any single frame. This is the number that makes a hostile peer
// harmless: receive-side memory per connection is bounded by it regardless of what the
// header claims (SPEC S7). It is a constant, not a negotiated value, on purpose -- a
// peer that could raise it could exhaust us.
inline constexpr uint32_t kMaxFrame = 1u << 20;  // 1 MiB

struct FrameHeader {
  uint32_t magic;        //  0  kFrameMagic
  uint8_t  type;         //  4  FrameType
  uint8_t  flags;        //  5  kFlag*
  uint16_t reserved;     //  6  must be zero; rejected otherwise, so it stays available
  uint32_t wire_len;     //  8  payload bytes actually on the wire
  uint32_t raw_len;      // 12  payload bytes after decompression (== wire_len if raw)
  uint64_t seq;          // 16  plan sequence number for kChunks, else 0
  uint32_t payload_crc;  // 24  CRC32C of the on-wire payload bytes
  uint32_t header_crc;   // 28  CRC32C of bytes 0..27 -- checked BEFORE any field above
};                       //     is used, because wire_len decides an allocation (S7)

static_assert(sizeof(FrameHeader) == 32, "frame header layout is a wire contract");
static_assert(alignof(FrameHeader) == 8, "seq must sit at a natural 8-byte boundary");
static_assert(offsetof(FrameHeader, magic) == 0);
static_assert(offsetof(FrameHeader, type) == 4);
static_assert(offsetof(FrameHeader, flags) == 5);
static_assert(offsetof(FrameHeader, reserved) == 6);
static_assert(offsetof(FrameHeader, wire_len) == 8);
static_assert(offsetof(FrameHeader, raw_len) == 12);
static_assert(offsetof(FrameHeader, seq) == 16);
static_assert(offsetof(FrameHeader, payload_crc) == 24);
static_assert(offsetof(FrameHeader, header_crc) == 28);

// The header CRC covers everything before itself. Named rather than written as `28`
// in three places, because the two must never drift apart.
inline constexpr size_t kHeaderCrcCoverage = offsetof(FrameHeader, header_crc);
static_assert(kHeaderCrcCoverage == 28);

// ---------------------------------------------------------------------------
// On-disk chunk record (SPEC 3.5) -- 48 bytes, little-endian, then the payload
// ---------------------------------------------------------------------------
//
// Self-describing on purpose: a container file alone is enough to rebuild the chunk
// index, and a torn tail from a kill -9 mid-append is detectable -- recovery truncates
// at the first record whose header is short, whose magic is wrong, or whose CRC fails.
inline constexpr uint32_t kChunkMagic =
    (uint32_t{'C'}) | (uint32_t{'H'} << 8) | (uint32_t{'N'} << 16) | (uint32_t{'K'} << 24);

struct ChunkRecordHeader {
  uint32_t magic;      //  0  kChunkMagic -- resynchronisation point in a damaged file
  uint32_t length;     //  4  payload bytes
  uint32_t crc32c;     //  8  of the payload: detects bit rot and torn tails
  uint32_t flags;      // 12
  Digest32 fp;         // 16  full SHA-256 of the payload
};

static_assert(sizeof(ChunkRecordHeader) == 48, "chunk record layout is a disk contract");
static_assert(offsetof(ChunkRecordHeader, magic) == 0);
static_assert(offsetof(ChunkRecordHeader, length) == 4);
static_assert(offsetof(ChunkRecordHeader, crc32c) == 8);
static_assert(offsetof(ChunkRecordHeader, flags) == 12);
static_assert(offsetof(ChunkRecordHeader, fp) == 16);

// ---------------------------------------------------------------------------
// Session / resume parameters (SPEC 3.7)
// ---------------------------------------------------------------------------
//
// How often the target fsyncs its contiguous high-water mark. This is a pure
// performance/durability trade with NO correctness content: it bounds how much gets
// re-sent after a drop (SPEC S6), and if the checkpoint is lost entirely the fallback
// re-negotiation still avoids re-sending stored chunks. Tuned in T9 with a measurement.
inline constexpr uint64_t kCheckpointBytes = 8ull * 1024 * 1024;

}  // namespace wanrep
