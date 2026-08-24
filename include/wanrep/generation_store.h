// Generation visibility: the mechanism behind consistency contract C1 (SPEC 3.1, 3.5).
//
// THE ONE IDEA:
//   A generation becomes visible when -- and ONLY when -- its COMMIT record is durable in
//   the append-only GENERATIONS journal. The manifest file is written and fsynced BEFORE
//   that record, and is completely inert until the record names it. So the entire
//   "target is never in a torn state" claim reduces to a single atomic fact on disk,
//   rather than to a protocol that has to be argued about.
//
//   commit sequence (SPEC S4 ordering):
//     caller fsyncs chunk data                      <- data durable
//     write manifest: tmp -> fsync -> rename -> fsync(dir)   <- durable but INVISIBLE
//     append COMMIT{gen, manifest digest}, fsync    <- THE ATOMIC INSTANT
//     caller may now ACK
//
//   Crash before the COMMIT record -> generation invisible; the manifest is garbage that
//   recovery removes, and the chunks are inert (nothing references them). Crash after it,
//   before the ACK -> the generation IS committed, the source retries, and commit() is
//   idempotent so the retry succeeds. Both paths are idempotent, which is the property
//   every recovery path in this system is required to have.
//
// WHY THE JOURNAL STORES OPAQUE BYTES:
//   This layer never parses a manifest. It stores bytes and a digest. That keeps the
//   durability mechanism independent of the manifest format (T7), and it means a manifest
//   format change cannot introduce a crash-consistency bug.
#pragma once

#include <algorithm>
#include <cstring>
#include <map>
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

// 'G','C','M','T' little-endian.
inline constexpr uint32_t kCommitMagic =
    (uint32_t{'G'}) | (uint32_t{'C'} << 8) | (uint32_t{'M'} << 16) | (uint32_t{'T'} << 24);

// A dataset name becomes a directory name, so it is attacker-controlled input that turns
// into a path (SPEC S12). Rejected rather than sanitized: silently rewriting a name means
// two different names can collide on one directory.
inline bool valid_dataset_name(const std::string& n) {
  if (n.empty() || n.size() > 128) return false;
  if (n == "." || n == "..") return false;
  for (const char c : n) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    if (!ok) return false;
  }
  // Belt and braces: no leading dot, so a name can never become a hidden file or "..".
  return n[0] != '.';
}

struct CommitRecord {
  uint64_t generation = 0;
  Digest32 manifest_digest{};
  std::string dataset;
};

class GenerationStore {
 public:
  // 56-byte fixed header, then the dataset name.
  static constexpr size_t kRecHeader = 56;
  static constexpr uint16_t kMaxNameLen = 128;

  static Result<std::unique_ptr<GenerationStore>> open(const std::string& root) {
    auto gs = std::unique_ptr<GenerationStore>(new GenerationStore(root));
    WANREP_TRY(make_dirs(root + "/datasets"));
    auto j = File::open_rw(root + "/GENERATIONS");
    if (!j.ok()) return j.error();
    gs->journal_ = std::make_unique<File>(std::move(*j));
    WANREP_TRY(gs->replay());
    WANREP_TRY(gs->sweep_uncommitted_manifests());
    return gs;
  }

  // Commits a generation. Idempotent for an identical (dataset, gen, digest); a DIFFERENT
  // digest for an already-committed generation is a protocol error, not an overwrite --
  // a committed generation is immutable, and quietly replacing one would break C1 for any
  // reader that had already observed it.
  Result<void> commit(const std::string& dataset, uint64_t generation, ByteSpan manifest) {
    if (!valid_dataset_name(dataset)) return err(Err::kInvalidArgument, "dataset name");
    const Digest32 digest = sha256(manifest);

    {
      std::lock_guard<std::mutex> g(mu_);
      auto it = committed_.find(key(dataset, generation));
      if (it != committed_.end()) {
        if (it->second == digest) return {};  // idempotent retry after a lost ACK
        return err(Err::kExists, "generation already committed with different content");
      }
    }

    if (WANREP_FAULT(FaultPoint::kBeforeCommit) == FaultKind::kIoError) {
      return err(Err::kFaultInjected, "before_commit");
    }

    // Step 1: the manifest becomes durable, but stays invisible -- nothing names it yet.
    const std::string dir = manifest_dir(dataset);
    WANREP_TRY(make_dirs(dir));
    WANREP_TRY(write_file_atomic(manifest_path(dataset, generation), manifest));

    // The sharpest injection point in the system: manifest durable, COMMIT record not
    // written. A correct implementation must come back from this with the generation
    // INVISIBLE and the store clean (SPEC 3.8, C1).
    if (WANREP_FAULT(FaultPoint::kAfterManifestFsyncBeforeCommit) == FaultKind::kKillSelf) {
      ::_exit(137);
    }

    // Step 2: the atomic instant.
    std::lock_guard<std::mutex> g(mu_);
    WANREP_TRY(append_record_locked(dataset, generation, digest));
    committed_[key(dataset, generation)] = digest;
    return {};
  }

  std::vector<uint64_t> visible_generations(const std::string& dataset) const {
    std::lock_guard<std::mutex> g(mu_);
    std::vector<uint64_t> out;
    for (const auto& [k, _] : committed_) {
      if (k.first == dataset) out.push_back(k.second);
    }
    std::sort(out.begin(), out.end());
    return out;
  }

  Result<uint64_t> latest_generation(const std::string& dataset) const {
    const auto v = visible_generations(dataset);
    if (v.empty()) return err(Err::kNotFound, "no committed generation for " + dataset);
    return v.back();
  }

  bool is_committed(const std::string& dataset, uint64_t generation) const {
    std::lock_guard<std::mutex> g(mu_);
    return committed_.find(key(dataset, generation)) != committed_.end();
  }

  Result<std::vector<uint8_t>> manifest_bytes(const std::string& dataset,
                                              uint64_t generation) const {
    Digest32 expected{};
    {
      std::lock_guard<std::mutex> g(mu_);
      auto it = committed_.find(key(dataset, generation));
      if (it == committed_.end()) return err(Err::kNotFound, "generation not committed");
      expected = it->second;
    }
    auto bytes = read_whole_file(manifest_path(dataset, generation));
    if (!bytes.ok()) {
      // The COMMIT record is the authority and it says this exists. If the file is gone
      // or unreadable, the store is genuinely corrupt -- the ordering guarantees the
      // manifest was durable before the record that names it was written.
      return err(Err::kCorrupt, "committed manifest is missing: " + bytes.error().message());
    }
    if (sha256(ByteSpan(bytes->data(), bytes->size())) != expected) {
      return err(Err::kCorrupt, "committed manifest digest mismatch");
    }
    return bytes;
  }

  std::vector<std::string> datasets() const {
    std::lock_guard<std::mutex> g(mu_);
    std::vector<std::string> out;
    // committed_ is a std::map keyed on (dataset, generation), so it is already sorted by
    // dataset name and equal names are adjacent -- one comparison per entry suffices.
    for (const auto& [k, _] : committed_) {
      if (out.empty() || out.back() != k.first) out.push_back(k.first);
    }
    return out;
  }

  struct VerifyReport {
    size_t generations = 0;
    size_t problems = 0;
    std::vector<std::string> detail;
  };

  // Every COMMIT record must resolve to a manifest whose digest matches. This is the
  // half of the oracle that checks C1 directly.
  Result<VerifyReport> verify() const {
    VerifyReport rep;
    std::vector<std::pair<std::string, uint64_t>> keys;
    {
      std::lock_guard<std::mutex> g(mu_);
      for (const auto& [k, _] : committed_) keys.push_back(k);
    }
    for (const auto& k : keys) {
      rep.generations++;
      auto m = manifest_bytes(k.first, k.second);
      if (!m.ok()) {
        rep.problems++;
        if (rep.detail.size() < 32) {
          rep.detail.push_back(k.first + "/g" + std::to_string(k.second) + ": " +
                               m.error().message());
        }
      }
    }
    return rep;
  }

  // C1 stated as a check: the visible set must be a contiguous prefix 0..k with no hole.
  // A hole would mean a generation became visible before one it depends on, which is the
  // exact failure the commit ordering exists to prevent.
  bool is_prefix_consistent(const std::string& dataset) const {
    const auto v = visible_generations(dataset);
    for (size_t i = 0; i < v.size(); i++) {
      if (v[i] != i) return false;
    }
    return true;
  }

  std::string manifest_path(const std::string& dataset, uint64_t generation) const {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "/g%010llu.man",
                  static_cast<unsigned long long>(generation));
    return manifest_dir(dataset) + buf;
  }

 private:
  using Key = std::pair<std::string, uint64_t>;

  explicit GenerationStore(std::string root) : root_(std::move(root)) {}

  static Key key(const std::string& d, uint64_t g) { return {d, g}; }
  std::string manifest_dir(const std::string& dataset) const {
    return root_ + "/datasets/" + dataset + "/manifests";
  }

  static void put_u32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = static_cast<uint8_t>(v >> (8 * i));
  }
  static void put_u64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = static_cast<uint8_t>(v >> (8 * i));
  }
  static uint32_t get_u32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(p[i]) << (8 * i);
    return v;
  }
  static uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
  }
  static uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
  }

  Result<void> append_record_locked(const std::string& dataset, uint64_t generation,
                                    const Digest32& digest) {
    const uint16_t name_len = static_cast<uint16_t>(dataset.size());
    const size_t rec_len = kRecHeader + name_len;
    std::vector<uint8_t> rec(rec_len, 0);
    put_u32(rec.data() + 0, kCommitMagic);
    put_u32(rec.data() + 4, static_cast<uint32_t>(rec_len));
    put_u64(rec.data() + 8, generation);
    std::memcpy(rec.data() + 16, digest.data(), 32);
    rec[48] = static_cast<uint8_t>(name_len);
    rec[49] = static_cast<uint8_t>(name_len >> 8);
    rec[50] = 0;  // flags
    rec[51] = 0;
    std::memcpy(rec.data() + kRecHeader, dataset.data(), name_len);
    // CRC covers everything except the CRC field itself: bytes [0,52) and the name.
    const uint32_t c = crc32c(ByteSpan(rec.data() + kRecHeader, name_len),
                              crc32c(ByteSpan(rec.data(), 52)));
    put_u32(rec.data() + 52, c);

    WANREP_TRY(journal_->pwrite_all(ByteSpan(rec.data(), rec.size()), journal_size_));
    WANREP_TRY(journal_->fsync());  // the atomic instant
    journal_size_ += rec.size();
    return {};
  }

  // Replays the journal, stopping at the first record that is short, has a bad magic, or
  // fails its CRC -- a torn tail from a crash mid-append. Records are appended one at a
  // time and fsynced, so anything after a torn record cannot exist.
  Result<void> replay() {
    auto sz = journal_->size();
    if (!sz.ok()) return sz.error();
    const uint64_t file_size = *sz;
    uint64_t off = 0;
    while (off + kRecHeader <= file_size) {
      uint8_t hdr[kRecHeader];
      if (!journal_->pread_exact(hdr, kRecHeader, off).ok()) break;
      if (get_u32(hdr + 0) != kCommitMagic) break;
      const uint32_t rec_len = get_u32(hdr + 4);
      const uint16_t name_len = get_u16(hdr + 48);
      // Validate the declared lengths against the file and against the cap BEFORE using
      // them to size anything (SPEC S7 applies to disk as well as to the wire).
      if (name_len > kMaxNameLen) break;
      if (rec_len != kRecHeader + name_len) break;
      if (off + rec_len > file_size) break;

      std::vector<uint8_t> name(name_len);
      if (name_len > 0 && !journal_->pread_exact(name.data(), name_len, off + kRecHeader).ok()) {
        break;
      }
      const uint32_t c =
          crc32c(ByteSpan(name.data(), name_len), crc32c(ByteSpan(hdr, 52)));
      if (c != get_u32(hdr + 52)) break;  // torn tail

      CommitRecord r;
      r.generation = get_u64(hdr + 8);
      std::memcpy(r.manifest_digest.data(), hdr + 16, 32);
      r.dataset.assign(reinterpret_cast<const char*>(name.data()), name_len);
      if (valid_dataset_name(r.dataset)) {
        committed_[key(r.dataset, r.generation)] = r.manifest_digest;
      }
      off += rec_len;
    }
    if (off != file_size) WANREP_TRY(journal_->truncate(off));
    journal_size_ = off;
    return {};
  }

  // A manifest file that no COMMIT record names does not exist as far as any reader is
  // concerned (SPEC 3.5). Removing it at open time keeps that statement true on disk as
  // well as in the API, and makes a crashed commit leave no trace at all.
  Result<void> sweep_uncommitted_manifests() {
    // Deliberately conservative: only sweeps ".tmp" leftovers and manifests for
    // generations with no COMMIT record, and only in dataset directories we know about.
    // Never recurses outside root_/datasets.
    for (const auto& d : datasets()) {
      const std::string dir = manifest_dir(d);
      for (uint64_t gen = 0; gen < 4096; gen++) {
        const std::string p = manifest_path(d, gen);
        if (path_exists(p + ".tmp")) ::unlink((p + ".tmp").c_str());
        if (path_exists(p) && !is_committed(d, gen)) ::unlink(p.c_str());
      }
    }
    return {};
  }

  std::string root_;
  mutable std::mutex mu_;
  std::unique_ptr<File> journal_;
  uint64_t journal_size_ = 0;
  std::map<Key, Digest32> committed_;
};

}  // namespace wanrep
