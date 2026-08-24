// The target's store: chunks + generations, behind one lock and one open-time safety gate.
//
// TWO THINGS HAPPEN AT open() THAT ARE NOT BOOKKEEPING:
//
// 1. flock on <root>/LOCK, held for the process lifetime (SPEC S16). Two target processes
//    appending into one container would corrupt it.
//
// 2. probe_flock_exclusion() runs FIRST, and the store REFUSES TO OPEN where flock does
//    not actually exclude. T0 measured a filesystem where it silently does not -- the
//    virtiofs bind mount that Docker Desktop uses to share a macOS directory into the
//    container, where two independent open file descriptions BOTH acquire LOCK_EX with no
//    error (docs/CHALLENGES.md B2). That is the most natural place for a user to put a
//    store, and without this gate S16 would be unenforced with no diagnostic at all: the
//    first symptom would be a CRC failure days later, in a component nowhere near the
//    fault. A comment could not have fixed that. Refusing to start, with an error that
//    names its own cause, does.
#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "wanrep/chunk_store.h"
#include "wanrep/fsprobe.h"
#include "wanrep/generation_store.h"
#include "wanrep/io.h"
#include "wanrep/result.h"

namespace wanrep {

// 'W','T','G','T'
inline constexpr uint32_t kTargetMagic =
    (uint32_t{'W'}) | (uint32_t{'T'} << 8) | (uint32_t{'G'} << 16) | (uint32_t{'T'} << 24);
inline constexpr uint32_t kStoreVersion = 1;

struct TargetStoreOptions {
  // Escape hatch for the one legitimate case: a read-only inspection of a store that
  // lives on a filesystem without working locks. Never set by the server.
  bool allow_unsafe_filesystem = false;
};

class TargetStore {
 public:
  using Options = TargetStoreOptions;

  static Result<std::unique_ptr<TargetStore>> open(const std::string& root,
                                                   TargetStoreOptions opt = {}) {
    WANREP_TRY(make_dirs(root));

    // Gate first, before anything is created or modified.
    std::string detail;
    const FlockSupport support = probe_flock_exclusion(root, &detail);
    if (support != FlockSupport::kExclusive && !opt.allow_unsafe_filesystem) {
      return err(Err::kUnsafeFilesystem,
                 "flock exclusion is not enforceable at " + root + " (" +
                     to_string(support) + ": " + detail +
                     "). Two processes could write this store with no error. Use "
                     "container-local storage, not a bind mount. See CHALLENGES.md B2.");
    }

    auto store = std::unique_ptr<TargetStore>(new TargetStore(root));
    store->flock_support_ = support;

    auto lock = File::open_rw(root + "/LOCK");
    if (!lock.ok()) return lock.error();
    WANREP_TRY(lock->lock_exclusive());  // Err::kLocked if another process holds it
    store->lock_ = std::make_unique<File>(std::move(*lock));

    WANREP_TRY(store->init_superblock());

    auto chunks = ChunkStore::open(root);
    if (!chunks.ok()) return chunks.error();
    store->chunks_ = std::move(*chunks);

    auto gens = GenerationStore::open(root);
    if (!gens.ok()) return gens.error();
    store->generations_ = std::move(*gens);

    return store;
  }

  ChunkStore& chunks() { return *chunks_; }
  const ChunkStore& chunks() const { return *chunks_; }
  GenerationStore& generations() { return *generations_; }
  const GenerationStore& generations() const { return *generations_; }
  const std::string& root() const { return root_; }
  FlockSupport flock_support() const { return flock_support_; }

  // THE ORACLE (SPEC R3.4). Every fault-injection case ends here, and they all end here
  // in the SAME way -- so no failure gets a bespoke standard of proof.
  struct VerifyReport {
    size_t chunks = 0;
    size_t generations = 0;
    size_t problems = 0;
    std::vector<std::string> detail;
    bool ok() const { return problems == 0; }
  };

  Result<VerifyReport> verify(bool deep) const {
    VerifyReport rep;
    auto c = chunks_->verify(deep);
    if (!c.ok()) return c.error();
    rep.chunks = c->chunks;
    rep.problems += c->problems;
    for (auto& d : c->detail) rep.detail.push_back("chunk " + d);

    auto g = generations_->verify();
    if (!g.ok()) return g.error();
    rep.generations = g->generations;
    rep.problems += g->problems;
    for (auto& d : g->detail) rep.detail.push_back("generation " + d);

    // C1 itself: the visible set must be a contiguous prefix for every dataset.
    for (const auto& ds : generations_->datasets()) {
      if (!generations_->is_prefix_consistent(ds)) {
        rep.problems++;
        rep.detail.push_back("dataset " + ds + ": visible generations are not a prefix (C1)");
      }
    }
    return rep;
  }

 private:
  explicit TargetStore(std::string root) : root_(std::move(root)) {}

  // The superblock is written once and verified thereafter. Its job is to fail loudly if
  // a store written by a different version -- or a directory that is not a store at all --
  // is opened, rather than being silently appended to.
  Result<void> init_superblock() {
    const std::string path = root_ + "/TARGET";
    if (path_exists(path)) {
      auto bytes = read_whole_file(path, 4096);
      if (!bytes.ok()) return bytes.error();
      if (bytes->size() < 12) return err(Err::kCorrupt, "TARGET superblock too short");
      const uint8_t* p = bytes->data();
      uint32_t magic = 0, version = 0;
      for (int i = 0; i < 4; i++) magic |= static_cast<uint32_t>(p[i]) << (8 * i);
      for (int i = 0; i < 4; i++) version |= static_cast<uint32_t>(p[4 + i]) << (8 * i);
      if (magic != kTargetMagic) return err(Err::kCorrupt, "not a wanrep target store");
      if (version != kStoreVersion) {
        return err(Err::kUnsupported,
                   "store version " + std::to_string(version) + ", this build speaks " +
                       std::to_string(kStoreVersion));
      }
      return {};
    }
    std::vector<uint8_t> sb(12, 0);
    for (int i = 0; i < 4; i++) sb[i] = static_cast<uint8_t>(kTargetMagic >> (8 * i));
    for (int i = 0; i < 4; i++) sb[4 + i] = static_cast<uint8_t>(kStoreVersion >> (8 * i));
    for (int i = 0; i < 4; i++) sb[8 + i] = static_cast<uint8_t>(kAvgChunk >> (8 * i));
    return write_file_atomic(path, ByteSpan(sb.data(), sb.size()));
  }

  std::string root_;
  std::unique_ptr<File> lock_;
  std::unique_ptr<ChunkStore> chunks_;
  std::unique_ptr<GenerationStore> generations_;
  FlockSupport flock_support_ = FlockSupport::kUnavailable;
};

}  // namespace wanrep
