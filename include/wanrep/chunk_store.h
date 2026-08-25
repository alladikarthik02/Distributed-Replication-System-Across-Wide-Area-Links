// The target's content-addressed chunk store (SPEC 3.5).
//
// WHAT MAKES THIS SAFE RATHER THAN CLEVER:
//   Chunks are immutable and named by the SHA-256 of their own bytes, so storing one is
//   idempotent. That single property is why a dropped link is recoverable at all
//   (SPEC 3.0): re-sending a chunk the target already has is a no-op, never a
//   corruption, so resume needs no distributed bookkeeping to be correct.
//
// THE RULE THE RECEIVER NEVER RELAXES (SPEC S17):
//   put() recomputes SHA-256 over the received bytes and refuses the chunk if it does
//   not hash to its claimed name. A buggy source, a corrupted frame that slipped past
//   the CRCs, and a hostile peer are all the same case and are all handled the same way.
//   The target's correctness must not depend on the source being correct -- otherwise
//   "the target stayed correct after every simulated failure" (the third headline claim) would be
//   conditional on the thing we are injecting failures into.
//
// WHY THE INDEX IS NOT AN AUTHORITY:
//   Containers are self-describing: every record carries its own length, CRC and
//   fingerprint. So the fingerprint -> location index can be rebuilt by scanning them,
//   which demotes index durability from a correctness problem to a startup cost. Nothing
//   here is fsynced to keep the index alive; only chunk data is.
//
// WHAT THIS DELIBERATELY IS NOT:
//   Project #1 (`dedupe`) claims a *memory-efficient* index and earns that claim with a
//   sharded open-addressed table measured against a baseline. This project claims no such
//   thing, so this index is a plain sharded unordered_map. Re-implementing the compact
//   table here would be borrowing another project's headline claim without its measurements.
#pragma once

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "wanrep/crc32c.h"
#include "wanrep/fault.h"
#include "wanrep/io.h"
#include "wanrep/result.h"
#include "wanrep/sha256.h"
#include "wanrep/types.h"

namespace wanrep {

struct ChunkLoc {
  uint32_t container = 0;
  uint64_t offset = 0;  // offset of the RECORD HEADER, not of the payload
  uint32_t length = 0;
};

class ChunkStore {
 public:
  // 128 MiB per container: large enough that a big store is not thousands of open files,
  // small enough that a torn tail costs one bounded rescan.
  static constexpr uint64_t kContainerTarget = 128ull * 1024 * 1024;
  static constexpr size_t kShards = 256;

  static Result<std::unique_ptr<ChunkStore>> open(const std::string& root) {
    const std::string dir = root + "/chunks";
    WANREP_TRY(make_dirs(dir));
    auto store = std::unique_ptr<ChunkStore>(new ChunkStore(dir));
    WANREP_TRY(store->recover());
    return store;
  }

  bool has(const Digest32& fp) const {
    Shard& s = shard_for(fp);
    std::shared_lock<std::shared_mutex> g(s.mu);
    return s.map.find(fp) != s.map.end();
  }

  // Idempotent. Storing a chunk that is already present is a successful no-op -- that is
  // what makes a resumed transfer safe when it re-sends the in-flight window (SPEC 3.7).
  Result<void> put(const Digest32& fp, ByteSpan bytes) {
    if (bytes.size() == 0) return err(Err::kInvalidArgument, "empty chunk");
    if (bytes.size() > kMaxChunk) {
      return err(Err::kTooLarge, "chunk exceeds kMaxChunk");
    }

    // SPEC S17. Before anything is written, before the index is touched: does this
    // actually hash to the name it was sent under?
    const Digest32 actual = sha256(bytes);
    if (actual != fp) {
      return err(Err::kFingerprintMismatch,
                 "claimed " + to_hex(fp) + " but content hashes to " + to_hex(actual));
    }

    if (has(fp)) return {};

    ChunkRecordHeader hdr{};
    hdr.magic = kChunkMagic;
    hdr.length = static_cast<uint32_t>(bytes.size());
    hdr.crc32c = crc32c(bytes);
    hdr.flags = 0;
    hdr.fp = fp;

    uint32_t container_id = 0;
    uint64_t offset = 0;
    {
      // The container lock covers only the offset reservation and the append. Note that
      // NO index shard lock is held here: SPEC 3.6's lock order (session -> shard ->
      // container) permits shard-then-container, but holding a shard across file I/O
      // would stall every concurrent lookup on that shard for the duration of a write.
      // Taking them strictly sequentially instead of nested is stronger than the rule
      // requires and costs nothing.
      std::lock_guard<std::mutex> g(write_mu_);
      WANREP_TRY(ensure_writable_locked(sizeof(hdr) + bytes.size()));
      container_id = active_id_;
      offset = active_size_;

      std::vector<uint8_t> record(sizeof(hdr) + bytes.size());
      encode_header(hdr, record.data());
      std::memcpy(record.data() + sizeof(hdr), bytes.data(), bytes.size());
      WANREP_TRY(active_->pwrite_all(ByteSpan(record.data(), record.size()), offset));
      active_size_ += record.size();
      dirty_ = true;
    }

    insert_index(fp, ChunkLoc{container_id, offset, static_cast<uint32_t>(bytes.size())});
    return {};
  }

  Result<std::vector<uint8_t>> get(const Digest32& fp) const {
    ChunkLoc loc;
    {
      Shard& s = shard_for(fp);
      std::shared_lock<std::shared_mutex> g(s.mu);
      auto it = s.map.find(fp);
      if (it == s.map.end()) return err(Err::kNotFound, "chunk " + to_hex(fp));
      loc = it->second;
    }
    return read_at(loc, /*verify_fp=*/true);
  }

  // Durability barrier. Called before a generation's manifest is published, so that no
  // reference can be published ahead of its data (SPEC S4).
  Result<void> sync() {
    {
      std::lock_guard<std::mutex> g(write_mu_);
      if (!dirty_ || !active_) return {};
      WANREP_TRY(active_->fsync());
      dirty_ = false;
    }
    // The chunk data is durable and nothing references it yet. A crash HERE is the case
    // SPEC S4's ordering exists to survive: the manifest has not been written, so the
    // generation is invisible and the chunks are inert.
    if (WANREP_FAULT(FaultPoint::kAfterChunkFsyncBeforeManifest) == FaultKind::kIoError) {
      return err(Err::kFaultInjected, "after chunk fsync");
    }
    return {};
  }

  size_t chunk_count() const {
    size_t n = 0;
    for (const auto& s : shards_) {
      std::shared_lock<std::shared_mutex> g(s.mu);
      n += s.map.size();
    }
    return n;
  }

  uint64_t bytes_stored() const {
    std::lock_guard<std::mutex> g(write_mu_);
    return total_bytes_;
  }

  // The store half of the verification oracle (SPEC 4.1 / R3.4). deep=true re-reads every
  // chunk and re-verifies both its CRC and its SHA-256; shallow only checks that every
  // indexed location is inside a container.
  // A region of a container that recovery could not parse but that was NOT a torn tail --
  // i.e. valid records were found after it. See recover() for why the distinction matters.
  struct Damage {
    uint32_t container = 0;
    uint64_t offset = 0;
    uint64_t length = 0;
  };

  struct VerifyReport {
    size_t chunks = 0;
    size_t problems = 0;
    std::vector<std::string> detail;
  };

  // Damage found during recovery. Non-empty means bytes were lost to corruption rather
  // than to a crash, which is a different conversation with the operator: a torn tail is
  // normal after kill -9, mid-file damage is a failing disk.
  std::vector<Damage> damage() const {
    std::lock_guard<std::mutex> g(write_mu_);
    return damage_;
  }

  Result<VerifyReport> verify(bool deep) const {
    VerifyReport rep;
    {
      // Damage discovered at recovery time is a problem even though nothing is wrong with
      // what SURVIVED. Omitting it is how a store that silently lost records reports clean.
      std::lock_guard<std::mutex> g(write_mu_);
      for (const auto& d : damage_) {
        rep.problems++;
        if (rep.detail.size() < 32) {
          rep.detail.push_back("container " + std::to_string(d.container) + ": " +
                               std::to_string(d.length) + " unparseable bytes at offset " +
                               std::to_string(d.offset) + " (corruption, not a torn tail)");
        }
      }
    }
    for (const auto& s : shards_) {
      std::shared_lock<std::shared_mutex> g(s.mu);
      for (const auto& [fp, loc] : s.map) {
        rep.chunks++;
        auto bytes = read_at(loc, /*verify_fp=*/true);
        if (!bytes.ok()) {
          rep.problems++;
          if (rep.detail.size() < 32) {
            rep.detail.push_back(to_hex(fp) + ": " + bytes.error().message());
          }
          continue;
        }
        if (deep) {
          if (sha256(ByteSpan(bytes->data(), bytes->size())) != fp) {
            rep.problems++;
            if (rep.detail.size() < 32) rep.detail.push_back(to_hex(fp) + ": digest mismatch");
          }
        }
      }
    }
    return rep;
  }

  // Rebuilds the index from the containers alone, proving the index is a cache. Returns
  // the number of chunks found.
  Result<size_t> rebuild_index() {
    for (auto& s : shards_) {
      std::unique_lock<std::shared_mutex> g(s.mu);
      s.map.clear();
    }
    WANREP_TRY(recover());
    return chunk_count();
  }

  size_t container_count() const {
    std::lock_guard<std::mutex> g(write_mu_);
    return containers_.size();
  }

 private:
  struct Shard {
    mutable std::shared_mutex mu;
    std::unordered_map<Digest32, ChunkLoc, DigestHash> map;
  };

  explicit ChunkStore(std::string dir) : dir_(std::move(dir)) {}

  Shard& shard_for(const Digest32& fp) const {
    // The top byte of a SHA-256 is as good a shard selector as any function of it, and
    // it costs nothing.
    return const_cast<Shard&>(shards_[fp[0]]);
  }

  void insert_index(const Digest32& fp, ChunkLoc loc) {
    Shard& s = shard_for(fp);
    std::unique_lock<std::shared_mutex> g(s.mu);
    s.map.emplace(fp, loc);  // emplace, not insert_or_assign: first writer wins
  }

  static void encode_header(const ChunkRecordHeader& h, uint8_t* out) {
    // Explicit little-endian field writes rather than a memcpy of the struct. The struct
    // layout is asserted in types.h, but the ON-DISK format must not depend on the
    // compiler agreeing with us -- that is a contract with future readers, not with this
    // translation unit.
    put_u32(out + 0, h.magic);
    put_u32(out + 4, h.length);
    put_u32(out + 8, h.crc32c);
    put_u32(out + 12, h.flags);
    std::memcpy(out + 16, h.fp.data(), 32);
  }

  static bool decode_header(const uint8_t* in, ChunkRecordHeader& h) {
    h.magic = get_u32(in + 0);
    h.length = get_u32(in + 4);
    h.crc32c = get_u32(in + 8);
    h.flags = get_u32(in + 12);
    std::memcpy(h.fp.data(), in + 16, 32);
    return h.magic == kChunkMagic;
  }

  static void put_u32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
  }
  static uint32_t get_u32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  }

  static std::string container_name(uint32_t id) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "c%08u.dat", id);
    return buf;
  }

  Result<void> ensure_writable_locked(size_t need) {
    if (active_ && active_size_ + need <= kContainerTarget) return {};
    const uint32_t id = containers_.empty() ? 0 : static_cast<uint32_t>(containers_.size());
    auto f = File::open_rw(dir_ + "/" + container_name(id));
    if (!f.ok()) return f.error();
    auto sz = f->size();
    if (!sz.ok()) return sz.error();
    containers_.push_back(std::make_shared<File>(std::move(*f)));
    active_ = containers_.back();
    active_id_ = id;
    active_size_ = *sz;
    return {};
  }


  static constexpr uint64_t kNoResync = ~uint64_t{0};

  // Fully validates a record at `off`: magic, a length inside the format's bounds, the
  // payload actually present, and the CRC over that payload. A false positive would be a
  // 32-bit CRC collision on top of a 4-byte magic match, which is not a risk worth
  // engineering around.
  static bool parse_record_at(File& f, uint64_t off, uint64_t file_size,
                              ChunkRecordHeader& h) {
    if (off + sizeof(ChunkRecordHeader) > file_size) return false;
    uint8_t hbuf[sizeof(ChunkRecordHeader)];
    if (!f.pread_exact(hbuf, sizeof(hbuf), off).ok()) return false;
    if (!decode_header(hbuf, h)) return false;
    if (h.length == 0 || h.length > kMaxChunk) return false;
    if (off + sizeof(hbuf) + h.length > file_size) return false;
    std::vector<uint8_t> payload(h.length);
    if (!f.pread_exact(payload.data(), payload.size(), off + sizeof(hbuf)).ok()) return false;
    return crc32c(ByteSpan(payload.data(), payload.size())) == h.crc32c;
  }

  // Scans forward for the next byte offset holding a record that validates. Buffered in
  // 1 MiB windows with a 3-byte overlap so a magic straddling a window boundary is not
  // missed -- one pread per byte would be 128 million syscalls on a full container.
  static uint64_t find_next_record(File& f, uint64_t from, uint64_t file_size) {
    static constexpr size_t kWindow = 1u << 20;
    const uint8_t magic_le[4] = {
        static_cast<uint8_t>(kChunkMagic), static_cast<uint8_t>(kChunkMagic >> 8),
        static_cast<uint8_t>(kChunkMagic >> 16), static_cast<uint8_t>(kChunkMagic >> 24)};
    std::vector<uint8_t> buf;
    uint64_t pos = from;
    while (pos + sizeof(ChunkRecordHeader) <= file_size) {
      const size_t want = static_cast<size_t>(std::min<uint64_t>(kWindow, file_size - pos));
      buf.resize(want);
      if (!f.pread_exact(buf.data(), want, pos).ok()) return kNoResync;
      for (size_t i = 0; i + 4 <= want; i++) {
        if (std::memcmp(buf.data() + i, magic_le, 4) != 0) continue;
        ChunkRecordHeader h{};
        if (parse_record_at(f, pos + i, file_size, h)) return pos + i;
      }
      if (want < kWindow) break;
      pos += want - 3;  // overlap, so a magic split across the boundary is still found
    }
    return kNoResync;
  }

  Result<std::vector<uint8_t>> read_at(const ChunkLoc& loc, bool verify_fp) const {
    std::shared_ptr<File> f;
    {
      std::lock_guard<std::mutex> g(write_mu_);
      if (loc.container >= containers_.size()) {
        return err(Err::kCorrupt, "index points at a container that does not exist");
      }
      f = containers_[loc.container];
    }
    uint8_t hbuf[sizeof(ChunkRecordHeader)];
    WANREP_TRY(f->pread_exact(hbuf, sizeof(hbuf), loc.offset));
    ChunkRecordHeader h{};
    if (!decode_header(hbuf, h)) return err(Err::kCorrupt, "bad chunk magic");
    if (h.length != loc.length || h.length == 0 || h.length > kMaxChunk) {
      return err(Err::kCorrupt, "chunk length disagrees with the index");
    }
    std::vector<uint8_t> payload(h.length);
    WANREP_TRY(f->pread_exact(payload.data(), payload.size(), loc.offset + sizeof(hbuf)));
    if (crc32c(ByteSpan(payload.data(), payload.size())) != h.crc32c) {
      return err(Err::kCorrupt, "chunk CRC mismatch (bit rot or torn write)");
    }
    if (verify_fp && sha256(ByteSpan(payload.data(), payload.size())) != h.fp) {
      return err(Err::kCorrupt, "chunk content does not match its stored fingerprint");
    }
    return payload;
  }

  // Opens every container and scans it, rebuilding the index and TRUNCATING a torn tail.
  //
  // A crash mid-append leaves a partial record. Recovery stops at the first record that
  // is short, has a bad magic, or fails its CRC, and truncates the file there. That is
  // safe because the append is the last step for a chunk: a truncated chunk was never
  // referenced by a committed generation, since chunk data is fsynced before any manifest
  // that names it is published (SPEC S4).
  Result<void> recover() {
    std::lock_guard<std::mutex> g(write_mu_);
    containers_.clear();
    damage_.clear();
    total_bytes_ = 0;
    for (uint32_t id = 0;; id++) {
      const std::string path = dir_ + "/" + container_name(id);
      if (!path_exists(path)) break;
      auto f = File::open_rw(path, /*create=*/false);
      if (!f.ok()) return f.error();
      auto shared = std::make_shared<File>(std::move(*f));
      containers_.push_back(shared);
      auto sz = shared->size();
      if (!sz.ok()) return sz.error();

      uint64_t off = 0;
      const uint64_t file_size = *sz;
      while (off + sizeof(ChunkRecordHeader) <= file_size) {
        ChunkRecordHeader h{};
        if (parse_record_at(*shared, off, file_size, h)) {
          Shard& s = shard_for(h.fp);
          {
            std::unique_lock<std::shared_mutex> sg(s.mu);
            s.map.emplace(h.fp, ChunkLoc{id, off, h.length});
          }
          off += sizeof(ChunkRecordHeader) + h.length;
          total_bytes_ += h.length;
          continue;
        }

        // This record did not parse. Two very different things look identical here, and
        // treating them the same is a data-loss bug:
        //
        //   * A TORN TAIL -- a crash partway through an append. Everything after it is
        //     garbage or absent, and truncating is correct.
        //   * MID-FILE DAMAGE -- bit rot, a bad sector, a stray write. Valid records
        //     still follow it, and truncating would silently DELETE them. Measured: one
        //     flipped byte in the first of five records destroyed all five.
        //
        // So we resynchronize instead of guessing: scan forward for the next record that
        // fully validates. Finding one proves this was not a tail. This is the job the
        // per-record magic was put there to do (types.h calls it "a resynchronization
        // point in a damaged file"); until now that was a comment, not a mechanism.
        const uint64_t resync = find_next_record(*shared, off + 1, file_size);
        if (resync == kNoResync) {
          WANREP_TRY(shared->truncate(off));  // genuine torn tail
          break;
        }
        damage_.push_back(Damage{id, off, resync - off});
        off = resync;
      }
      active_ = shared;
      active_id_ = id;
      active_size_ = std::min(off, file_size);
    }
    return {};
  }

  std::string dir_;
  mutable std::mutex write_mu_;
  std::vector<std::shared_ptr<File>> containers_;
  std::shared_ptr<File> active_;
  uint32_t active_id_ = 0;
  uint64_t active_size_ = 0;
  uint64_t total_bytes_ = 0;
  bool dirty_ = false;
  std::vector<Damage> damage_;
  mutable Shard shards_[kShards];
};

}  // namespace wanrep
