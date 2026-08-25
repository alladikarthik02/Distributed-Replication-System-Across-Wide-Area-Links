// The framing layer of SPEC 3.2: 32-byte header + payload, over the abstract Link.
//
// WHAT THIS LAYER IS AND IS NOT:
//   It moves self-delimiting, CRC-checked frames. It does NOT decompress -- a frame with
//   kFlagCompressed comes out of FrameReader with its payload exactly as it arrived on
//   the wire, and SPEC 3.4's decoder runs above. That split is deliberate and it is a
//   safety boundary, not a taste preference: the LZ decoder is the code that runs on
//   attacker-chosen bytes, and it is far easier to argue it is bounds-safe when its
//   input is "a buffer of at most kMaxFrame bytes whose CRC already matched and whose
//   output bound raw_len was already range-checked" than when it is entangled with
//   socket reads that can return short.
//
// THE READ ORDER IS THE WHOLE POINT (SPEC S7):
//   To read a frame you must first believe wire_len, because wire_len decides how many
//   bytes you allocate and read. A payload CRC cannot save you there -- by the time you
//   could check it you have already acted on the bad length. So the header carries its
//   OWN CRC over bytes 0..27, and FrameReader::next() validates it BEFORE reading any
//   other field, then range-checks wire_len and raw_len against kMaxFrame, and only then
//   allocates. Get this order wrong and a single flipped bit in a length field turns a
//   corrupt frame into a 4 GiB allocation. Every step below is numbered to match.
//
// WHY EXPLICIT LITTLE-ENDIAN BYTE WRITES INSTEAD OF memcpy OF THE STRUCT:
//   types.h asserts FrameHeader's layout, so a memcpy would work today, on this
//   compiler, on this architecture. But the wire format is a contract with a peer we did
//   not compile, and SPEC 2.5 records why this specific shortcut is dangerous here: on a
//   big-endian host every length and sequence number would be byte-swapped AND THE MAGIC
//   WOULD STILL MATCH (the magic is symmetric under nothing, but it is read as bytes by
//   the peer's own swapped reader), so the corruption would be silent rather than loud.
//   Explicit byte writes make the wire format independent of the struct, which is why
//   FrameHeader appears in types.h as a layout assertion and nowhere in this file's
//   encode/decode path.
//
// WHY THE WRITER COALESCES HEADER AND PAYLOAD INTO ONE write_all:
//   Two write_all calls per frame is the classic write-write-read pattern, and on a link
//   with Nagle enabled and delayed ACKs at the peer it can cost a full round trip per
//   frame -- on the exact kind of link SPEC 3.2 says round trips, not bytes, are the
//   enemy. The price is one memcpy of at most kMaxFrame into a buffer reused across
//   frames (so: no per-frame allocation). A memcpy runs at gigabytes per second against
//   a 12.5 MB/s WAN link; the copy is free and the round trip is not.
//
// THREADING: neither class is thread-safe, and neither needs to be. SPEC 3.6 gives the
// socket to exactly one sender thread, which is what removes the lock these would
// otherwise need and what guarantees frames are never interleaved.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "wanrep/crc32c.h"
#include "wanrep/link.h"
#include "wanrep/result.h"
#include "wanrep/types.h"

namespace wanrep {

// Every flag bit defined by this protocol version. Unknown bits are rejected on both
// sides for the same reason SPEC 3.2 rejects a non-zero `reserved`: a bit that peers are
// allowed to set and we are allowed to ignore is a bit that can never be given a
// meaning later without a silent behaviour change on old nodes. The magic pins the
// version, so a new flag arrives with a new magic.
inline constexpr uint8_t kKnownFrameFlags = kFlagCompressed | kFlagLastSlice;

// Written as a switch with no `default` on purpose: adding a member to FrameType without
// updating this is then a -Wswitch warning, which check.sh builds with -Werror. A
// `default: return false` would have compiled silently and quietly rejected the new type
// on the wire.
inline bool is_known_frame_type(uint8_t t) {
  switch (static_cast<FrameType>(t)) {
    case FrameType::kHello:
    case FrameType::kHelloAck:
    case FrameType::kSessionStart:
    case FrameType::kSessionResume:
    case FrameType::kSessionAck:
    case FrameType::kManifest:
    case FrameType::kNeed:
    case FrameType::kChunks:
    case FrameType::kCheckpoint:
    case FrameType::kGenCommit:
    case FrameType::kCommitAck:
    case FrameType::kError:
    case FrameType::kBye:
      return true;
  }
  return false;
}

struct Frame {
  FrameType type = FrameType::kHello;
  uint8_t flags = 0;
  uint64_t seq = 0;

  // Payload bytes after decompression. For an uncompressed frame this always equals
  // payload.size(), even when the peer spelled it 0 on the wire (see kRawLenRule below),
  // so the layer above never has to special-case "0 means not applicable".
  uint32_t raw_len = 0;

  // Exactly the on-wire payload bytes -- still compressed if (flags & kFlagCompressed).
  std::vector<uint8_t> payload;

  bool compressed() const { return (flags & kFlagCompressed) != 0; }
};

namespace frame_detail {

inline void put_u16_le(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}
inline void put_u32_le(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}
inline void put_u64_le(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; i++) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
inline uint16_t load_u16_le(const uint8_t* p) {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
inline uint32_t load_u32_le(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t load_u64_le(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(p[i]) << (8 * i);
  return v;
}

// Field offsets, named so the writer and the reader cannot drift apart. They mirror
// types.h's static_asserts, but they are the values this file actually uses -- the
// struct is a layout *check*, not the encoder.
inline constexpr size_t kOffMagic = 0;
inline constexpr size_t kOffType = 4;
inline constexpr size_t kOffFlags = 5;
inline constexpr size_t kOffReserved = 6;
inline constexpr size_t kOffWireLen = 8;
inline constexpr size_t kOffRawLen = 12;
inline constexpr size_t kOffSeq = 16;
inline constexpr size_t kOffPayloadCrc = 24;
inline constexpr size_t kOffHeaderCrc = 28;
inline constexpr size_t kHeaderBytes = sizeof(FrameHeader);  // 32

static_assert(kHeaderBytes == 32);
static_assert(kOffHeaderCrc == kHeaderCrcCoverage);

// Lays out one header into `h[32]`, including its own CRC. Shared by FrameWriter and by
// the tests that craft hostile headers, so a test can never accidentally exercise a
// different serializer than production does.
inline void encode_header(uint8_t* h, uint8_t type, uint8_t flags, uint32_t wire_len,
                          uint32_t raw_len, uint64_t seq, uint32_t payload_crc) {
  put_u32_le(h + kOffMagic, kFrameMagic);
  h[kOffType] = type;
  h[kOffFlags] = flags;
  put_u16_le(h + kOffReserved, 0);
  put_u32_le(h + kOffWireLen, wire_len);
  put_u32_le(h + kOffRawLen, raw_len);
  put_u64_le(h + kOffSeq, seq);
  put_u32_le(h + kOffPayloadCrc, payload_crc);
  put_u32_le(h + kOffHeaderCrc, crc32c(ByteSpan(h, kHeaderCrcCoverage)));
}

}  // namespace frame_detail

// THE raw_len RULE (step 5 of the read order), and why it is this and not something
// tighter or looser:
//
//   compressed   -> raw_len >= wire_len, and raw_len <= kMaxFrame.
//   uncompressed -> raw_len == wire_len, or raw_len == 0 meaning "not applicable".
//
// Compressed: raw_len is the decompressor's output bound. A frame claiming to expand to
// FEWER bytes than it occupies is the shape of an attack on that bound -- it is trying
// to get a decoder to under-allocate and then write past it -- and it is also something
// an honest sender cannot produce, because SPEC S14 sends the batch raw whenever
// compression did not shrink it. We require >= rather than the strictly tighter > on
// purpose: > would encode the compressor's tie-break policy ("not smaller means raw")
// into the framing layer, and if T3 ever changes that tie-break the framing layer should
// not have to be re-argued. >= is the bound the decoder actually needs.
//
// Uncompressed: SPEC 3.2 says raw_len "== wire_len when not compressed", and the writer
// always emits exactly that, so the wire has one spelling. The reader also accepts 0
// because that is what a minimal peer naturally emits for a control frame that has no
// notion of decompressed size, and accepting it is free: for an uncompressed frame the
// payload length is wire_len and raw_len is never used for anything. (Contrast varint.h,
// where two spellings ARE rejected -- there the encoding gets digested and compared, so
// two spellings of one value is a real hazard. A frame header is CRC'd, never digested.)
class FrameWriter {
 public:
  explicit FrameWriter(Link& l) : link_(l) {}

  // Errors here are kInvalidArgument, not protocol errors: a bad argument is OUR bug,
  // caught at the boundary, and confusing it with "the peer sent nonsense" would send a
  // developer looking at the wrong node.
  Result<void> write(FrameType t, uint64_t seq, ByteSpan payload, uint8_t flags = 0,
                     uint32_t raw_len = 0) {
    using namespace frame_detail;

    if (payload.size() > kMaxFrame) {
      return err(Err::kTooLarge, "payload exceeds kMaxFrame");
    }
    if (!is_known_frame_type(static_cast<uint8_t>(t))) {
      return err(Err::kInvalidArgument, "unknown FrameType");
    }
    if ((flags & ~kKnownFrameFlags) != 0) {
      return err(Err::kInvalidArgument, "unknown frame flag bits");
    }

    const uint32_t wire_len = static_cast<uint32_t>(payload.size());
    uint32_t on_wire_raw_len = raw_len;
    if ((flags & kFlagCompressed) != 0) {
      if (raw_len < wire_len) {
        return err(Err::kInvalidArgument, "compressed frame with raw_len < wire_len");
      }
      if (raw_len > kMaxFrame) return err(Err::kTooLarge, "raw_len exceeds kMaxFrame");
    } else {
      if (raw_len != 0 && raw_len != wire_len) {
        return err(Err::kInvalidArgument, "uncompressed frame with raw_len != wire_len");
      }
      on_wire_raw_len = wire_len;  // normalize: the wire carries one spelling
    }

    // A zero-length payload has a well-defined CRC (0), not a special case: crc32c()
    // never dereferences the pointer when the length is 0, so an empty BYE or
    // COMMIT_ACK goes through exactly the same path as a 1 MiB CHUNKS frame.
    const uint32_t payload_crc = crc32c(payload);

    // One buffer, reused across frames -- see the header comment on write-write-read.
    buf_.resize(kHeaderBytes + wire_len);
    encode_header(buf_.data(), static_cast<uint8_t>(t), flags, wire_len, on_wire_raw_len,
                  seq, payload_crc);
    if (wire_len) std::memcpy(buf_.data() + kHeaderBytes, payload.data(), wire_len);

    WANREP_TRY(write_all(link_, buf_.data(), buf_.size()));
    frames_++;
    return {};
  }

  uint64_t frames_written() const { return frames_; }

 private:
  Link& link_;
  std::vector<uint8_t> buf_;
  uint64_t frames_ = 0;
};

class FrameReader {
 public:
  explicit FrameReader(Link& l) : link_(l) {}

  // Err::kClosed ONLY at a clean end-of-stream between frames. A stream that ends part
  // way through a header or a payload is kShortRead, and a peer that vanished is kReset
  // -- SPEC 3.7's resume logic branches on exactly that three-way distinction, and
  // collapsing "the peer finished" into "the peer died" (or worse, the other way) would
  // let a truncated transfer be committed as a complete one.
  Result<Frame> next() {
    using namespace frame_detail;

    uint8_t h[kHeaderBytes];

    // --- (1) the header, in full -------------------------------------------------
    // read_exact already turns a mid-structure EOF into kShortRead and leaves a clean
    // EOF at offset 0 as kClosed, which is precisely the boundary this function reports.
    {
      auto r = read_exact(link_, h, kHeaderBytes);
      if (!r.ok()) return r.error();
    }

    // --- (2) header_crc, BEFORE any other field is touched (SPEC S7) --------------
    const uint32_t want_hcrc = load_u32_le(h + kOffHeaderCrc);
    const uint32_t got_hcrc = crc32c(ByteSpan(h, kHeaderCrcCoverage));
    if (got_hcrc != want_hcrc) {
      return err(Err::kBadHeaderCrc, "header CRC mismatch");
    }

    // --- (3) structural validation, still before any allocation -------------------
    if (load_u32_le(h + kOffMagic) != kFrameMagic) {
      return err(Err::kBadMagic, "not a wanrep frame");
    }
    if (load_u16_le(h + kOffReserved) != 0) {
      return err(Err::kMalformed, "reserved bytes are not zero");
    }
    const uint8_t type = h[kOffType];
    if (!is_known_frame_type(type)) return err(Err::kMalformed, "unknown frame type");
    const uint8_t flags = h[kOffFlags];
    if ((flags & ~kKnownFrameFlags) != 0) {
      return err(Err::kMalformed, "unknown frame flag bits");
    }

    const uint32_t wire_len = load_u32_le(h + kOffWireLen);
    const uint32_t raw_len = load_u32_le(h + kOffRawLen);
    // The two range checks that make a hostile peer harmless. Everything above this
    // point has read only fixed 32 bytes; nothing below allocates until both pass.
    if (wire_len > kMaxFrame) return err(Err::kTooLarge, "wire_len exceeds kMaxFrame");
    if (raw_len > kMaxFrame) return err(Err::kTooLarge, "raw_len exceeds kMaxFrame");

    // --- (4) the raw_len rule (documented above FrameWriter) ----------------------
    const bool compressed = (flags & kFlagCompressed) != 0;
    uint32_t effective_raw_len = raw_len;
    if (compressed) {
      if (raw_len < wire_len) {
        return err(Err::kMalformed, "compressed frame expands to less than itself");
      }
    } else {
      if (raw_len != 0 && raw_len != wire_len) {
        return err(Err::kMalformed, "uncompressed frame with raw_len != wire_len");
      }
      effective_raw_len = wire_len;
    }

    // --- (5) only now is it safe to allocate --------------------------------------
    Frame f;
    f.type = static_cast<FrameType>(type);
    f.flags = flags;
    f.seq = load_u64_le(h + kOffSeq);
    f.raw_len = effective_raw_len;
    f.payload.resize(wire_len);

    if (wire_len) {
      auto r = read_exact(link_, f.payload.data(), wire_len);
      if (!r.ok()) {
        // A clean EOF *here* is not a clean EOF: we are mid-frame, and the header we
        // already accepted promised these bytes. read_exact can only report kClosed when
        // zero payload bytes had arrived, so this remap is what covers the case of a
        // stream cut exactly on the header/payload boundary.
        if (r.error().code == Err::kClosed) {
          return err(Err::kShortRead, "stream ended before the payload");
        }
        return r.error();
      }
    }

    // --- (6) payload integrity ----------------------------------------------------
    if (crc32c(ByteSpan(f.payload.data(), f.payload.size())) !=
        load_u32_le(h + kOffPayloadCrc)) {
      return err(Err::kBadPayloadCrc, "payload CRC mismatch");
    }

    frames_++;
    return f;
  }

  uint64_t frames_read() const { return frames_; }

 private:
  Link& link_;
  uint64_t frames_ = 0;
};

}  // namespace wanrep
