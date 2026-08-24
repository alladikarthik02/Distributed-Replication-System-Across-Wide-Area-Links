// Resumable transfers (SPEC 3.7, R2.4, R2.5, S5, S6).
//
// THE POINT THAT IS EASY TO MISS, AND IS THE WHOLE DESIGN:
//   None of this is required for correctness. Every chunk is content-addressed and
//   therefore idempotent, so a resumed transfer that re-sends data is merely wasteful,
//   never wrong. If every file in sessions/ were deleted, the system would still be
//   correct -- it would re-negotiate, discover that the target already holds most of the
//   chunks, and ask for the remainder. The checkpoint saves TWO ROUND TRIPS. Content
//   addressing saves the data.
//
//   That is why the durable state here is deliberately tiny, and why losing it is tested
//   (test_resume deletes the session file and still asserts almost nothing is re-sent).
//   Keeping durability out of the correctness path is the same decision as making the
//   chunk index rebuildable, applied to a second problem.
//
// WHY A CONTIGUOUS HIGH-WATER MARK AND NOT "HIGHEST SEEN":
//   Batches may be acknowledged out of order (compression happens on several threads).
//   A "highest seq seen" mark would skip over gaps, and resuming past a gap would leave
//   a chunk permanently missing while the transfer reported success. The mark is
//   therefore the largest h such that EVERY index below h has arrived; out-of-order
//   arrivals wait in a bounded window until they become contiguous. Being conservative
//   here costs a little re-sending and cannot lose data.
#pragma once

#include <bit>
#include <cstring>
#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "wanrep/crc32c.h"
#include "wanrep/fault.h"
#include "wanrep/io.h"
#include "wanrep/result.h"
#include "wanrep/sha256.h"
#include "wanrep/types.h"

namespace wanrep {

// The out-of-order window. 65 536 indices is an 8 KiB bitmap and, at 8 KiB chunks, spans
// half a gigabyte of in-flight data -- far beyond any plausible bandwidth-delay product
// (SPEC 3.2 puts a 100 Mbit/s / 100 ms link at 1.25 MB). A peer that sends beyond it is
// not merely early, it is misbehaving, so the bound doubles as a protocol check and as
// the thing that keeps receive-side memory constant (SPEC S10).
inline constexpr uint64_t kOutOfOrderWindow = 1u << 16;

class HighWaterTracker {
 public:
  explicit HighWaterTracker(uint64_t plan_size, uint64_t base = 0)
      : plan_size_(plan_size), base_(base), bits_((kOutOfOrderWindow + 63) / 64, 0) {}

  // Records that plan indices [seq, seq+count) have been durably stored. Returns
  // Err::kProtocol if the range lies beyond the window -- which is a peer bug or an
  // attack, never a legitimate reordering.
  Result<void> mark_range(uint64_t seq, uint64_t count) {
    if (count == 0) return {};
    if (seq > plan_size_ || count > plan_size_ || seq + count > plan_size_) {
      return err(Err::kProtocol, "acknowledged range extends past the send plan");
    }
    for (uint64_t i = 0; i < count; i++) {
      const uint64_t s = seq + i;
      if (s < base_) continue;  // a duplicate from a resumed transfer: idempotent, ignore
      const uint64_t rel = s - base_;
      if (rel >= kOutOfOrderWindow) {
        return err(Err::kProtocol, "sequence " + std::to_string(s) + " is beyond the " +
                                       std::to_string(kOutOfOrderWindow) + "-index window");
      }
      bits_[rel / 64] |= (uint64_t{1} << (rel % 64));
    }
    advance();
    return {};
  }

  uint64_t contiguous() const { return base_; }
  bool complete() const { return base_ >= plan_size_; }
  uint64_t plan_size() const { return plan_size_; }

 private:
  // Slides the window forward over every index that has become contiguous.
  //
  // Scanned a WORD at a time, not a bit at a time. The naive version walks up to 65 536
  // bits on every single mark_range() call, which turns a per-chunk operation into a
  // per-chunk-times-window operation -- invisible in a unit test with ten chunks and
  // quadratic on a real transfer with millions.
  void advance() {
    uint64_t moved = 0;
    const size_t words = bits_.size();
    size_t w = 0;
    while (w < words && bits_[w] == ~uint64_t{0}) {
      moved += 64;
      w++;
    }
    if (w < words) {
      // The first word with a gap: countr_one gives the run of set bits below it.
      moved += static_cast<uint64_t>(std::countr_one(bits_[w]));
    }
    if (moved > kOutOfOrderWindow) moved = kOutOfOrderWindow;
    if (moved == 0) return;
    base_ += moved;
    shift_left(moved);
  }

  void shift_left(uint64_t n) {
    const uint64_t words = n / 64;
    const uint64_t rem = n % 64;
    const size_t total = bits_.size();
    if (words >= total) {
      std::fill(bits_.begin(), bits_.end(), 0);
      return;
    }
    for (size_t i = 0; i < total; i++) {
      const size_t src = i + static_cast<size_t>(words);
      uint64_t v = (src < total) ? bits_[src] : 0;
      if (rem != 0) {
        v >>= rem;
        const size_t src2 = src + 1;
        if (src2 < total) v |= bits_[src2] << (64 - rem);
      }
      bits_[i] = v;
    }
  }

  uint64_t plan_size_;
  uint64_t base_;
  std::vector<uint64_t> bits_;
};

// What the target durably remembers about an in-flight job.
struct SessionState {
  std::string session_id;
  std::string dataset;
  uint64_t generation = 0;
  Digest32 manifest_digest{};
  uint64_t plan_size = 0;
  uint64_t high_water = 0;
  uint64_t bytes_received = 0;
};

// 'W','S','E','S'
inline constexpr uint32_t kSessionMagic =
    (uint32_t{'W'}) | (uint32_t{'S'} << 8) | (uint32_t{'E'} << 16) | (uint32_t{'S'} << 24);

class SessionJournal {
 public:
  static Result<std::unique_ptr<SessionJournal>> open(const std::string& root) {
    const std::string dir = root + "/sessions";
    WANREP_TRY(make_dirs(dir));
    return std::unique_ptr<SessionJournal>(new SessionJournal(dir));
  }

  // A session id must be safe as a filename for the same reason a dataset name must be
  // (SPEC S12): it arrives from the peer and becomes a path.
  static bool valid_session_id(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    for (const char c : id) {
      const bool ok = (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9') || c == '-';
      if (!ok) return false;
    }
    return true;
  }

  Result<void> save(const SessionState& st) {
    if (!valid_session_id(st.session_id)) return err(Err::kInvalidArgument, "session id");
    if (WANREP_FAULT(FaultPoint::kOnCheckpointWrite) == FaultKind::kIoError) {
      return err(Err::kFaultInjected, "checkpoint write");
    }
    const auto bytes = encode(st);
    // Written atomically, so a crash mid-checkpoint leaves the PREVIOUS checkpoint intact
    // rather than a torn one. A torn checkpoint would still be safe (it fails its CRC and
    // is discarded, falling back to re-negotiation) -- but "safe" and "free" are different,
    // and the atomic write costs nothing here.
    return write_file_atomic(path_for(st.session_id), ByteSpan(bytes.data(), bytes.size()));
  }

  Result<SessionState> load(const std::string& id) const {
    if (!valid_session_id(id)) return err(Err::kInvalidArgument, "session id");
    const std::string p = path_for(id);
    if (!path_exists(p)) return err(Err::kNotFound, "no such session");
    auto bytes = read_whole_file(p, 4096);
    if (!bytes.ok()) return bytes.error();
    return decode(ByteSpan(bytes->data(), bytes->size()));
  }

  Result<void> erase(const std::string& id) {
    if (!valid_session_id(id)) return err(Err::kInvalidArgument, "session id");
    ::unlink(path_for(id).c_str());
    return {};
  }

  // Deterministic session ids: same job, same id. That means a source that crashes before
  // recording the id it was given can still find its session by recomputing it, instead of
  // having to durably remember a random number -- one fewer thing on the correctness path.
  static std::string session_id_for(const std::string& dataset, uint64_t generation,
                                    const Digest32& manifest_digest) {
    Sha256 h;
    h.update(as_bytes(std::string_view(dataset)));
    uint8_t g[8];
    for (int i = 0; i < 8; i++) g[i] = static_cast<uint8_t>(generation >> (8 * i));
    h.update(g, sizeof(g));
    h.update(ByteSpan(manifest_digest.data(), manifest_digest.size()));
    const Digest32 d = h.finish();
    return to_hex(ByteSpan(d.data(), 16));  // 128 bits: collision-free for this purpose
  }

 private:
  explicit SessionJournal(std::string dir) : dir_(std::move(dir)) {}
  std::string path_for(const std::string& id) const { return dir_ + "/" + id + ".ses"; }

  static void put_u64(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 0; i < 8; i++) o.push_back(static_cast<uint8_t>(v >> (8 * i)));
  }
  static uint64_t get_u64(ByteSpan b, size_t at) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(b[at + i]) << (8 * i);
    return v;
  }

  static std::vector<uint8_t> encode(const SessionState& st) {
    std::vector<uint8_t> o;
    for (int i = 0; i < 4; i++) o.push_back(static_cast<uint8_t>(kSessionMagic >> (8 * i)));
    put_u64(o, st.generation);
    put_u64(o, st.plan_size);
    put_u64(o, st.high_water);
    put_u64(o, st.bytes_received);
    o.insert(o.end(), st.manifest_digest.begin(), st.manifest_digest.end());
    o.push_back(static_cast<uint8_t>(st.session_id.size()));
    o.push_back(static_cast<uint8_t>(st.dataset.size()));
    o.insert(o.end(), st.session_id.begin(), st.session_id.end());
    o.insert(o.end(), st.dataset.begin(), st.dataset.end());
    const uint32_t c = crc32c(ByteSpan(o.data(), o.size()));
    for (int i = 0; i < 4; i++) o.push_back(static_cast<uint8_t>(c >> (8 * i)));
    return o;
  }

  static Result<SessionState> decode(ByteSpan b) {
    static constexpr size_t kFixed = 4 + 8 * 4 + 32 + 2;
    if (b.size() < kFixed + 4) return err(Err::kMalformed, "session too short");
    const size_t body = b.size() - 4;
    uint32_t stored = 0;
    for (int i = 0; i < 4; i++) stored |= static_cast<uint32_t>(b[body + i]) << (8 * i);
    if (crc32c(b.subspan(0, body)) != stored) {
      // Not fatal to the system: a bad checkpoint just means falling back to
      // re-negotiation, which is correct and costs two round trips (SPEC 3.7).
      return err(Err::kCorrupt, "session checkpoint CRC mismatch");
    }
    uint32_t magic = 0;
    for (int i = 0; i < 4; i++) magic |= static_cast<uint32_t>(b[i]) << (8 * i);
    if (magic != kSessionMagic) return err(Err::kBadMagic, "not a session file");

    SessionState st;
    st.generation = get_u64(b, 4);
    st.plan_size = get_u64(b, 12);
    st.high_water = get_u64(b, 20);
    st.bytes_received = get_u64(b, 28);
    std::memcpy(st.manifest_digest.data(), b.data() + 36, 32);
    const size_t id_len = b[68];
    const size_t ds_len = b[69];
    if (kFixed + id_len + ds_len != body) return err(Err::kMalformed, "session name lengths");
    st.session_id.assign(reinterpret_cast<const char*>(b.data() + kFixed), id_len);
    st.dataset.assign(reinterpret_cast<const char*>(b.data() + kFixed + id_len), ds_len);
    if (!valid_session_id(st.session_id)) return err(Err::kMalformed, "session id");
    // A high-water mark past the plan would let a resume skip chunks that never arrived.
    if (st.high_water > st.plan_size) return err(Err::kMalformed, "high water past plan end");
    return st;
  }

  std::string dir_;
};

}  // namespace wanrep
