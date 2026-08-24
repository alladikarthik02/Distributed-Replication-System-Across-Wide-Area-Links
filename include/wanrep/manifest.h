// The manifest: a generation's complete, self-contained description of a tree (SPEC 3.1).
//
// WHY A FULL MANIFEST AND NOT A DELTA:
//   Every generation ships the WHOLE description, not a diff against the previous one.
//   That sounds wasteful and is, on a nearly-unchanged tree, the dominant cost (SPEC 8.3
//   is honest about it). It buys something worth more: a target can be brought current
//   from ANY starting state -- including empty, including one that missed ten generations
//   -- with no delta chain that must all survive. The deltas are computed during
//   negotiation from what the target actually has (SPEC 3.3), not stored. Nothing on
//   disk has to be replayed in order for the target to be correct.
//
// THE CANONICAL CHUNK LIST IS THE PART THAT MAKES THE PROTOCOL CHEAP:
//   Both nodes derive the same ordered chunk list from the manifest alone, independently,
//   with no exchange. So the target's NEED reply is just a set of integers -- run-length
//   encoded, a handful of bytes to say "I don't need any of these four million chunks".
//   The ordering must therefore be a CONTRACT, not an implementation detail: files in
//   manifest order, chunks in file order, each fingerprint at its first occurrence. It is
//   differential-tested between the two sides for exactly that reason.
//
// EVERYTHING PARSED HERE IS HOSTILE INPUT (SPEC S12):
//   A manifest arrives over the network and its paths become paths on the target's disk.
//   Lengths and counts are validated against stated caps BEFORE they size an allocation,
//   and paths are REJECTED rather than sanitized -- silently rewriting a path means two
//   different manifests can collide on one file.
#pragma once

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "wanrep/chunker.h"
#include "wanrep/crc32c.h"
#include "wanrep/io.h"
#include "wanrep/result.h"
#include "wanrep/sha256.h"
#include "wanrep/types.h"
#include "wanrep/varint.h"

namespace wanrep {

// 'W','M','A','N'
inline constexpr uint32_t kManifestMagic =
    (uint32_t{'W'}) | (uint32_t{'M'} << 8) | (uint32_t{'A'} << 16) | (uint32_t{'N'} << 24);
inline constexpr uint32_t kManifestVersion = 1;

// Caps. Each exists so a malicious or corrupt manifest cannot turn a small buffer into a
// large allocation, and each is a number we can defend rather than a round one.
inline constexpr size_t kMaxPathLen = 4096;        // PATH_MAX on Linux
inline constexpr size_t kMaxFilesPerManifest = 1u << 22;   // 4.2M files
inline constexpr size_t kMaxChunksPerFile = 1u << 24;      // 16.7M x 2 KiB min = 32 GiB/file
inline constexpr size_t kMaxTotalChunkRefs = 1u << 26;     // 67M refs ~= 512 GiB at 8 KiB

// A relative path from a manifest becomes a path on the target's disk. Rejected, never
// sanitized: rewriting "a/../b" to "b" means two distinct manifest entries can silently
// become one file, and "which one won?" is not a question a replica should have.
inline bool valid_relative_path(std::string_view p) {
  if (p.empty() || p.size() > kMaxPathLen) return false;
  if (p.front() == '/') return false;            // absolute: escapes the target root
  if (p.back() == '/') return false;             // a trailing slash means a directory
  size_t start = 0;
  while (start <= p.size()) {
    const size_t slash = p.find('/', start);
    const size_t end = (slash == std::string_view::npos) ? p.size() : slash;
    const std::string_view comp = p.substr(start, end - start);
    if (comp.empty()) return false;              // "" from "//" or a leading/trailing slash
    if (comp == "." || comp == "..") return false;  // traversal
    for (const char c : comp) {
      // Control characters and NUL end paths early in C APIs; a backslash is a separator
      // on other platforms and a replica should not depend on which one reads it.
      if (static_cast<unsigned char>(c) < 0x20 || c == '\\') return false;
    }
    if (slash == std::string_view::npos) break;
    start = slash + 1;
  }
  return true;
}

struct ChunkRef {
  Digest32 fp{};
  uint32_t length = 0;
};

struct FileEntry {
  std::string path;        // relative to the tree root, '/' separated
  uint32_t mode = 0644;    // permission bits only; type bits are not replicated
  uint64_t size = 0;
  int64_t mtime_ns = 0;
  Digest32 digest{};       // whole-file SHA-256: the end-to-end check for S1
  std::vector<ChunkRef> chunks;
};

struct Manifest {
  uint64_t generation = 0;
  std::string dataset;
  std::vector<FileEntry> files;  // ALWAYS sorted by path -- see sort_for_determinism()

  uint64_t logical_bytes() const {
    uint64_t n = 0;
    for (const auto& f : files) n += f.size;
    return n;
  }

  size_t total_chunk_refs() const {
    size_t n = 0;
    for (const auto& f : files) n += f.chunks.size();
    return n;
  }

  // The manifest's byte ordering must not depend on the order readdir() happened to
  // return entries in, or two scans of an identical tree would produce different
  // manifests, different digests, and a different canonical chunk list.
  void sort_for_determinism() {
    std::sort(files.begin(), files.end(),
              [](const FileEntry& a, const FileEntry& b) { return a.path < b.path; });
  }

  std::vector<uint8_t> encode() const {
    std::vector<uint8_t> out;
    out.reserve(64 + total_chunk_refs() * 36);
    put_u32(out, kManifestMagic);
    put_u32(out, kManifestVersion);
    put_varint(out, generation);
    put_varint(out, dataset.size());
    out.insert(out.end(), dataset.begin(), dataset.end());
    put_varint(out, files.size());
    for (const auto& f : files) {
      put_varint(out, f.path.size());
      out.insert(out.end(), f.path.begin(), f.path.end());
      put_varint(out, f.mode);
      put_varint(out, f.size);
      put_varint(out, static_cast<uint64_t>(f.mtime_ns));
      out.insert(out.end(), f.digest.begin(), f.digest.end());
      put_varint(out, f.chunks.size());
      for (const auto& c : f.chunks) {
        out.insert(out.end(), c.fp.begin(), c.fp.end());
        put_varint(out, c.length);
      }
    }
    // Trailing CRC over everything above. The manifest also travels inside CRC-checked
    // frames, but it is STORED on the target too, where no frame protects it.
    put_u32(out, crc32c(ByteSpan(out.data(), out.size())));
    return out;
  }

  static Result<Manifest> decode(ByteSpan in) {
    if (in.size() < 12) return err(Err::kMalformed, "manifest too short");
    // Verify the CRC before trusting a single field, for the same reason the frame header
    // carries its own CRC (SPEC S7): the counts below decide allocations.
    const size_t body = in.size() - 4;
    if (crc32c(in.subspan(0, body)) != get_u32(in, body)) {
      return err(Err::kCorrupt, "manifest CRC mismatch");
    }
    size_t pos = 0;
    if (get_u32(in, pos) != kManifestMagic) return err(Err::kBadMagic, "not a manifest");
    pos += 4;
    const uint32_t version = get_u32(in, pos);
    pos += 4;
    if (version != kManifestVersion) {
      return err(Err::kUnsupported, "manifest version " + std::to_string(version));
    }

    Manifest m;
    uint64_t v = 0;
    if (!get_varint(in, pos, v)) return err(Err::kMalformed, "generation");
    m.generation = v;

    if (!get_varint(in, pos, v) || v > 128 || pos + v > body) {
      return err(Err::kMalformed, "dataset name");
    }
    m.dataset.assign(reinterpret_cast<const char*>(in.data() + pos), static_cast<size_t>(v));
    pos += static_cast<size_t>(v);

    if (!get_varint(in, pos, v) || v > kMaxFilesPerManifest) {
      return err(Err::kTooLarge, "file count");
    }
    const size_t file_count = static_cast<size_t>(v);
    // A count is only credible if the bytes to satisfy it exist. The cheapest possible
    // entry is 1 (path len) + 1 + 1 + 1 + 1 + 32 (digest) + 1 = 38 bytes, so a claim of
    // N files inside fewer than 38*N remaining bytes is a lie -- caught before reserving.
    if (file_count > (body - pos) / 38 + 1) return err(Err::kMalformed, "file count vs size");
    m.files.reserve(std::min<size_t>(file_count, 1u << 16));

    size_t total_refs = 0;
    for (size_t i = 0; i < file_count; i++) {
      FileEntry f;
      if (!get_varint(in, pos, v) || v > kMaxPathLen || pos + v > body) {
        return err(Err::kMalformed, "path length");
      }
      f.path.assign(reinterpret_cast<const char*>(in.data() + pos), static_cast<size_t>(v));
      pos += static_cast<size_t>(v);
      if (!valid_relative_path(f.path)) {
        return err(Err::kMalformed, "unsafe path in manifest: " + f.path);
      }
      if (!get_varint(in, pos, v)) return err(Err::kMalformed, "mode");
      f.mode = static_cast<uint32_t>(v & 07777);
      if (!get_varint(in, pos, v)) return err(Err::kMalformed, "size");
      f.size = v;
      if (!get_varint(in, pos, v)) return err(Err::kMalformed, "mtime");
      f.mtime_ns = static_cast<int64_t>(v);
      if (pos + 32 > body) return err(Err::kMalformed, "digest");
      std::memcpy(f.digest.data(), in.data() + pos, 32);
      pos += 32;

      if (!get_varint(in, pos, v) || v > kMaxChunksPerFile) {
        return err(Err::kTooLarge, "chunk count");
      }
      const size_t chunk_count = static_cast<size_t>(v);
      // Same reasoning: each chunk ref is at least 33 bytes on the wire.
      if (chunk_count > (body - pos) / 33 + 1) {
        return err(Err::kMalformed, "chunk count vs remaining size");
      }
      total_refs += chunk_count;
      if (total_refs > kMaxTotalChunkRefs) return err(Err::kTooLarge, "total chunk refs");
      f.chunks.resize(chunk_count);
      uint64_t sum = 0;
      for (size_t c = 0; c < chunk_count; c++) {
        if (pos + 32 > body) return err(Err::kMalformed, "chunk fp");
        std::memcpy(f.chunks[c].fp.data(), in.data() + pos, 32);
        pos += 32;
        if (!get_varint(in, pos, v) || v == 0 || v > kMaxChunk) {
          return err(Err::kMalformed, "chunk length");
        }
        f.chunks[c].length = static_cast<uint32_t>(v);
        sum += v;
      }
      // Internal consistency: the chunks must actually account for the file's size.
      // Without this a manifest could name a 10-byte file backed by a terabyte of chunks.
      if (sum != f.size) return err(Err::kMalformed, "chunk lengths do not sum to file size");
      m.files.push_back(std::move(f));
    }
    if (pos != body) return err(Err::kMalformed, "trailing bytes in manifest");

    // Paths must be strictly increasing: it enforces the deterministic ordering AND makes
    // duplicate paths impossible, which would otherwise be an ambiguity on materialize.
    for (size_t i = 1; i < m.files.size(); i++) {
      if (!(m.files[i - 1].path < m.files[i].path)) {
        return err(Err::kMalformed, "manifest paths are not strictly increasing");
      }
    }
    return m;
  }

  Digest32 digest() const {
    const auto bytes = encode();
    return sha256(ByteSpan(bytes.data(), bytes.size()));
  }

 private:
  static void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
  }
  static uint32_t get_u32(ByteSpan in, size_t at) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(in[at + i]) << (8 * i);
    return v;
  }
};

// THE CONTRACT (SPEC 3.3). Both nodes compute this from the manifest alone, independently,
// and must get byte-identical results -- the NEED reply is indices into it. Files in
// manifest order, chunks in file order, each fingerprint kept at its FIRST occurrence.
inline std::vector<Digest32> canonical_chunk_list(const Manifest& m) {
  std::vector<Digest32> out;
  out.reserve(m.total_chunk_refs());
  std::unordered_map<Digest32, uint8_t, DigestHash> seen;
  seen.reserve(m.total_chunk_refs() * 2);
  for (const auto& f : m.files) {
    for (const auto& c : f.chunks) {
      if (seen.emplace(c.fp, 1).second) out.push_back(c.fp);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Scanning a tree
// ---------------------------------------------------------------------------

struct ScanStats {
  size_t files = 0;
  size_t skipped = 0;
  uint64_t logical_bytes = 0;
  size_t chunk_refs = 0;
};

// Chunks one file, streaming. Never loads the whole file (SPEC S10): a replication source
// must not need memory proportional to the largest file in the tree.
inline Result<void> scan_file(const std::string& abs_path, const Chunker& chunker,
                              FileEntry& out) {
  auto f = File::open_read(abs_path);  // O_RDONLY: the source tree is never modified (S13)
  if (!f.ok()) return f.error();
  auto sz = f->size();
  if (!sz.ok()) return sz.error();

  Sha256 whole;
  std::vector<uint8_t> buf;
  uint64_t file_off = 0;   // absolute offset of buf[0]
  uint64_t read_off = 0;   // absolute offset of the next byte to read
  const uint64_t total = *sz;
  std::vector<uint8_t> io(256 * 1024);

  for (;;) {
    const bool at_eof = (read_off == total);
    const size_t cut = chunker.next_cut(ByteSpan(buf.data(), buf.size()), at_eof);
    if (cut > 0) {
      const ByteSpan chunk(buf.data(), cut);
      out.chunks.push_back(ChunkRef{sha256(chunk), static_cast<uint32_t>(cut)});
      whole.update(chunk);
      buf.erase(buf.begin(), buf.begin() + static_cast<long>(cut));
      file_off += cut;
      continue;
    }
    if (at_eof) break;
    const size_t want = static_cast<size_t>(std::min<uint64_t>(io.size(), total - read_off));
    WANREP_TRY(f->pread_exact(io.data(), want, read_off));
    buf.insert(buf.end(), io.data(), io.data() + want);
    read_off += want;
  }

  out.size = total;
  out.digest = whole.finish();
  return {};
}

// Walks `root` and produces a deterministic manifest.
//
// Symlinks, devices, sockets and FIFOs are SKIPPED, not followed and not replicated.
// Following them would let a link inside the tree pull in arbitrary data from outside it;
// replicating them is real work with its own semantics (relative vs absolute targets,
// dangling links) that nothing in the project claims. Skipped and counted, so the number
// is visible rather than the omission being silent.
inline Result<Manifest> scan_tree(const std::string& root, const std::string& dataset,
                                  uint64_t generation, const Chunker& chunker = Chunker(),
                                  ScanStats* stats = nullptr) {
  namespace fs = std::filesystem;
  Manifest m;
  m.dataset = dataset;
  m.generation = generation;

  std::error_code ec;
  const fs::path base = fs::path(root);
  if (!fs::is_directory(base, ec)) return err(Err::kNotFound, "not a directory: " + root);

  ScanStats local;
  fs::recursive_directory_iterator it(
      base, fs::directory_options::skip_permission_denied, ec);
  if (ec) return err(Err::kIo, "cannot walk " + root + ": " + ec.message());
  for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (ec) return err(Err::kIo, "walk failed: " + ec.message());
    // symlink_status, not status: we must not follow a link to decide what it is.
    const auto st = it->symlink_status(ec);
    if (ec) return err(Err::kIo, "stat failed: " + ec.message());
    if (fs::is_directory(st)) continue;
    if (!fs::is_regular_file(st)) {
      local.skipped++;
      continue;
    }
    const std::string rel = fs::relative(it->path(), base, ec).generic_string();
    if (ec) return err(Err::kIo, "relative path failed: " + ec.message());
    if (!valid_relative_path(rel)) {
      local.skipped++;
      continue;
    }
    FileEntry fe;
    fe.path = rel;
    fe.mode = static_cast<uint32_t>(fs::status(it->path(), ec).permissions()) & 07777;
    struct stat raw {};
    if (::stat(it->path().c_str(), &raw) == 0) {
      fe.mtime_ns = static_cast<int64_t>(raw.st_mtim.tv_sec) * 1000000000 +
                    raw.st_mtim.tv_nsec;
    }
    WANREP_TRY(scan_file(it->path().string(), chunker, fe));
    local.files++;
    local.logical_bytes += fe.size;
    local.chunk_refs += fe.chunks.size();
    m.files.push_back(std::move(fe));
  }
  m.sort_for_determinism();
  if (stats) *stats = local;
  return m;
}

}  // namespace wanrep
