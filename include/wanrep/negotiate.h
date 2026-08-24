// The set difference (SPEC 3.3): deciding which chunks actually cross the wire.
//
// This is the file that makes "sending only changed chunks" true, and the
// mechanism is smaller than it sounds: the target asks itself which fingerprints from the
// incoming manifest it does not already hold, and replies with those indices. There is no
// diff algorithm, no rename detection, no timestamp heuristic. Content addressing already
// did the work.
//
// A DELIBERATE DEPARTURE FROM THE ORIGINAL DESIGN (see docs/CHALLENGES.md B6):
//   SPEC 3.3 originally described a two-level scheme where files whose path, size, mode,
//   mtime and digest all matched the previous generation were skipped WITHOUT probing the
//   chunk store -- on the reasoning that a committed generation implies its chunks are
//   present. That is true, and it is still the wrong thing to do.
//
//   The probe is an in-memory hash lookup: ~40 ms for four million chunks, against a
//   transfer measured in minutes. It buys nothing worth having. What skipping it COSTS is
//   self-healing: if a chunk were lost to bit rot (which recovery can now detect and
//   report -- B4), a manifest-based skip would declare the file fine and the target would
//   stay silently broken. Probing makes the STORE authoritative rather than the previous
//   manifest, so damage is re-requested and repaired on the next generation, for free.
//
//   The previous manifest is still compared, but only to REPORT how much of the saving
//   came from unchanged files rather than from chunk-level dedup -- which SPEC 8.1
//   requires the bandwidth number to break down anyway.
#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "wanrep/chunk_store.h"
#include "wanrep/io.h"
#include "wanrep/manifest.h"
#include "wanrep/needset.h"
#include "wanrep/result.h"
#include "wanrep/types.h"

namespace wanrep {

struct NegotiationResult {
  NeedSet need;
  size_t chunks_total = 0;     // size of the canonical chunk list
  size_t chunks_needed = 0;
  uint64_t bytes_needed = 0;   // payload bytes the source will have to send
  uint64_t bytes_total = 0;    // payload bytes a full transfer would have sent

  // Attribution, for the bandwidth breakdown SPEC 8.1 insists on.
  size_t files_total = 0;
  size_t files_unchanged = 0;  // identical to the previous generation
  uint64_t bytes_in_unchanged_files = 0;
};

// Target side. `previous` may be null (first ever sync, or a re-negotiation after the
// session was lost).
inline NegotiationResult negotiate(const Manifest& incoming, const Manifest* previous,
                                   const ChunkStore& store) {
  NegotiationResult r;
  const std::vector<Digest32> canonical = canonical_chunk_list(incoming);
  r.chunks_total = canonical.size();
  r.files_total = incoming.files.size();

  // Length per fingerprint, for the byte accounting. First occurrence wins, matching the
  // canonical list's rule.
  std::unordered_map<Digest32, uint32_t, DigestHash> len_of;
  len_of.reserve(canonical.size() * 2);
  for (const auto& f : incoming.files) {
    for (const auto& c : f.chunks) len_of.emplace(c.fp, c.length);
  }

  if (previous != nullptr) {
    std::unordered_map<std::string, const FileEntry*> prev;
    prev.reserve(previous->files.size() * 2);
    for (const auto& f : previous->files) prev.emplace(f.path, &f);
    for (const auto& f : incoming.files) {
      auto it = prev.find(f.path);
      // The whole-file digest is in the comparison on purpose. Size and mtime agreeing is
      // a heuristic, and heuristics are how backup tools silently miss changed data.
      if (it != prev.end() && it->second->size == f.size && it->second->mode == f.mode &&
          it->second->mtime_ns == f.mtime_ns && it->second->digest == f.digest) {
        r.files_unchanged++;
        r.bytes_in_unchanged_files += f.size;
      }
    }
  }

  for (size_t i = 0; i < canonical.size(); i++) {
    const uint32_t len = len_of[canonical[i]];
    r.bytes_total += len;
    if (!store.has(canonical[i])) {
      r.need.add(i);
      r.chunks_needed++;
      r.bytes_needed += len;
    }
  }
  return r;
}

// Source side: the ordered list of chunks to send. A chunk's position in this plan is its
// `seq` on the wire, and the plan is derived deterministically from (manifest, need set),
// so it is STABLE across a disconnect and across the source's own thread scheduling --
// which is what lets a resumed transfer restart at an index rather than at a byte offset
// (SPEC 3.7).
struct SendPlan {
  std::vector<Digest32> chunks;   // ascending canonical index order
  std::vector<uint64_t> indices;  // the canonical index of chunks[i]
  uint64_t bytes = 0;

  size_t size() const { return chunks.size(); }
  bool empty() const { return chunks.empty(); }
};

inline SendPlan build_send_plan(const std::vector<Digest32>& canonical, const NeedSet& need,
                                const Manifest& m) {
  std::unordered_map<Digest32, uint32_t, DigestHash> len_of;
  len_of.reserve(canonical.size() * 2);
  for (const auto& f : m.files) {
    for (const auto& c : f.chunks) len_of.emplace(c.fp, c.length);
  }
  SendPlan plan;
  for (const uint64_t idx : need.to_vector()) {
    if (idx >= canonical.size()) continue;  // a peer's index we cannot honour; ignore it
    plan.indices.push_back(idx);
    plan.chunks.push_back(canonical[idx]);
    plan.bytes += len_of[canonical[idx]];
  }
  return plan;
}

// Produces a chunk's bytes from the source tree on demand.
//
// The (file, offset) of every chunk is DERIVABLE from the manifest -- chunk i of a file
// starts at the sum of the preceding chunk lengths -- so no extra index has to be built
// during the scan or carried across a resume. After a reconnect the source rebuilds this
// from the manifest it already has, in memory, without re-reading or re-chunking the tree.
class SourceChunkReader {
 public:
  SourceChunkReader(std::string root, const Manifest& m) : root_(std::move(root)) {
    // Paths are COPIED rather than pointed at. Holding a pointer into the caller's
    // Manifest would make this object silently outlive its data the first time a caller
    // re-scanned into the same variable -- and the symptom would be a garbage path in an
    // open() error, a long way from the cause.
    paths_.reserve(m.files.size());
    where_.reserve(m.total_chunk_refs() * 2);
    for (size_t fi = 0; fi < m.files.size(); fi++) {
      const FileEntry& f = m.files[fi];
      paths_.push_back(f.path);
      uint64_t off = 0;
      for (const auto& c : f.chunks) {
        where_.emplace(c.fp, Where{fi, off, c.length});
        off += c.length;
      }
    }
  }

  Result<std::vector<uint8_t>> read(const Digest32& fp) const {
    auto it = where_.find(fp);
    if (it == where_.end()) return err(Err::kNotFound, "chunk not in this manifest");
    const Where& w = it->second;
    const std::string path = root_ + "/" + paths_[w.file_index];
    auto f = File::open_read(path);  // read-only: the source tree is never modified (S13)
    if (!f.ok()) return f.error();
    std::vector<uint8_t> buf(w.length);
    WANREP_TRY(f->pread_exact(buf.data(), buf.size(), w.offset));
    // Cheap end-to-end check: if the tree changed under us since the scan, the bytes will
    // not hash to the name we are about to send them under -- and the target would reject
    // them anyway (S17). Catching it here names the real cause instead.
    if (sha256(ByteSpan(buf.data(), buf.size())) != fp) {
      return err(Err::kCorrupt, "source file changed since the scan: " + path);
    }
    return buf;
  }

 private:
  struct Where {
    size_t file_index;
    uint64_t offset;
    uint32_t length;
  };
  std::string root_;
  std::vector<std::string> paths_;
  std::unordered_map<Digest32, Where, DigestHash> where_;
};

// Rebuilds a committed generation's tree on the target and byte-compares nothing -- it
// simply writes the files. Verification is the caller's job, using the manifest's
// whole-file digests (SPEC S1).
inline Result<void> materialize(const Manifest& m, const ChunkStore& store,
                                const std::string& out_root) {
  WANREP_TRY(make_dirs(out_root));
  for (const auto& fe : m.files) {
    // Re-validated here even though decode() already checked it: this is the moment the
    // path becomes a real filesystem path, and a check at the point of use cannot be
    // bypassed by a caller that built a Manifest some other way (SPEC S12).
    if (!valid_relative_path(fe.path)) {
      return err(Err::kMalformed, "unsafe path at materialize: " + fe.path);
    }
    const std::string full = out_root + "/" + fe.path;
    WANREP_TRY(make_dirs(dirname_of(full)));

    std::vector<uint8_t> content;
    content.reserve(static_cast<size_t>(fe.size));
    for (const auto& c : fe.chunks) {
      auto bytes = store.get(c.fp);
      if (!bytes.ok()) return bytes.error();
      if (bytes->size() != c.length) return err(Err::kCorrupt, "chunk length mismatch");
      content.insert(content.end(), bytes->begin(), bytes->end());
    }
    if (content.size() != fe.size) return err(Err::kCorrupt, "assembled size mismatch");
    // The end-to-end check the whole design exists to make possible (SPEC S1).
    if (sha256(ByteSpan(content.data(), content.size())) != fe.digest) {
      return err(Err::kCorrupt, "materialized file does not match its manifest digest: " +
                                    fe.path);
    }
    WANREP_TRY(write_file_atomic(full, ByteSpan(content.data(), content.size())));
    if (::chmod(full.c_str(), static_cast<mode_t>(fe.mode & 07777)) != 0) {
      return err_errno(Err::kIo, "chmod " + full);
    }
  }
  return {};
}

}  // namespace wanrep
