// T6: the target store -- chunks, generations, and the guarantees that make consistency
// contract C1 true (SPEC 3.1, 3.5, S2, S3, S4, S12, S16, S17).
//
// The tests that carry the most weight here are the recovery ones. Anything can be made
// to work when nothing goes wrong; the claim here is that the target stays
// correct after a failure, and these are where that starts being earned.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "test.h"
#include "wanrep/target_store.h"

using namespace wanrep;

namespace {

inline void discard(bool) {}

// -Werror=unused-result is on for a reason (SPEC S11), and a (void) cast does NOT
// satisfy GCC's warn_unused_result -- correctly so, since discarding a status is exactly
// what the flag exists to prevent. So the helper actually inspects it, and callers who
// genuinely do not care (best-effort cleanup) discard a plain bool instead.
bool shell(const std::string& cmd) {
  const int rc = std::system(cmd.c_str());
  return rc == 0;
}

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 0x2545F4914F6CDD1Dull) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
};

// Every store in this suite lives on container-local storage, never on the bind mount.
// CHALLENGES B2: flock does not exclude there, so a store on /work would silently lose
// SPEC S16 -- and every I/O measurement would be a measurement of virtiofs.
struct TempStore {
  std::string path;
  explicit TempStore(const char* tag) {
    static std::atomic<int> counter{0};
    path = std::string("/tmp/wanrep_store_") + tag + "_" +
           std::to_string(counter.fetch_add(1)) + "_" + std::to_string(::getpid());
    discard(shell("rm -rf " + path));
  }
  ~TempStore() { discard(shell("rm -rf " + path)); }
};

std::vector<uint8_t> blob(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(rng.next() >> 24);
  return v;
}

ByteSpan sp(const std::vector<uint8_t>& v) { return ByteSpan(v.data(), v.size()); }

}  // namespace

// ---------------------------------------------------------------------------
// 1. Chunk store basics
// ---------------------------------------------------------------------------

TEST(chunk_store_round_trips_and_is_idempotent) {
  TempStore t("rt");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  auto& cs = (*s)->chunks();

  for (size_t n : {size_t{1}, size_t{2}, size_t{1000}, size_t{kMinChunk}, size_t{kAvgChunk},
                   size_t{kMaxChunk}}) {
    TCTX("n=" << n);
    const auto data = blob(n, testing::seed() + n);
    const Digest32 fp = sha256(sp(data));
    CHECK(cs.put(fp, sp(data)).ok());
    CHECK(cs.has(fp));
    // Idempotent: a resumed transfer re-sends its in-flight window (SPEC 3.7), so
    // storing a chunk twice must be a successful no-op, not an error and not a duplicate.
    CHECK(cs.put(fp, sp(data)).ok());
    auto got = cs.get(fp);
    REQUIRE(got.ok());
    CHECK(*got == data);
  }
}

// SPEC S17 -- the rule the receiver never relaxes.
TEST(chunk_store_rejects_a_chunk_that_does_not_hash_to_its_name) {
  TempStore t("s17");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  auto& cs = (*s)->chunks();

  const auto data = blob(4096, testing::seed());
  Digest32 lie = sha256(sp(data));
  lie[7] ^= 0x01;  // one bit off: the sender is buggy, or lying, or the wire flipped it

  auto r = cs.put(lie, sp(data));
  CHECK(!r.ok());
  CHECK(r.code() == Err::kFingerprintMismatch);
  CHECK(!cs.has(lie));
  CHECK_EQ(cs.chunk_count(), size_t{0});  // nothing was written at all

  auto v = (*s)->verify(true);
  REQUIRE(v.ok());
  CHECK_EQ(v->problems, size_t{0});
}

TEST(chunk_store_rejects_absurd_sizes) {
  TempStore t("size");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  auto& cs = (*s)->chunks();

  const std::vector<uint8_t> empty;
  CHECK(!cs.put(sha256(sp(empty)), sp(empty)).ok());

  const auto huge = blob(kMaxChunk + 1, testing::seed());
  auto r = cs.put(sha256(sp(huge)), sp(huge));
  CHECK(!r.ok());
  CHECK(r.code() == Err::kTooLarge);
}

TEST(chunk_store_get_of_an_absent_chunk_is_not_found) {
  TempStore t("miss");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  Digest32 nobody{};
  nobody[0] = 0xAB;
  auto r = (*s)->chunks().get(nobody);
  CHECK(!r.ok());
  CHECK(r.code() == Err::kNotFound);
}

// ---------------------------------------------------------------------------
// 2. Recovery -- the index is a cache, and a torn tail is survivable (SPEC S3)
// ---------------------------------------------------------------------------

TEST(chunk_store_index_is_rebuildable_from_containers_alone) {
  TempStore t("rebuild");
  std::vector<Digest32> fps;
  {
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    for (int i = 0; i < 50; i++) {
      const auto data = blob(1000 + static_cast<size_t>(i) * 37, testing::seed() + uint64_t(i));
      const Digest32 fp = sha256(sp(data));
      REQUIRE((*s)->chunks().put(fp, sp(data)).ok());
      fps.push_back(fp);
    }
    REQUIRE((*s)->chunks().sync().ok());
  }
  // Reopen from scratch: nothing but the container files survives.
  auto s2 = TargetStore::open(t.path);
  REQUIRE(s2.ok());
  CHECK_EQ((*s2)->chunks().chunk_count(), fps.size());
  for (const auto& fp : fps) CHECK((*s2)->chunks().has(fp));

  // And rebuilding explicitly must find exactly the same set.
  auto n = (*s2)->chunks().rebuild_index();
  REQUIRE(n.ok());
  CHECK_EQ(*n, fps.size());
}

// A crash mid-append leaves a partial record. Recovery must truncate at it, keep every
// complete record before it, and be idempotent.
TEST(chunk_store_recovers_from_a_torn_tail) {
  TempStore t("torn");
  std::vector<Digest32> fps;
  {
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    for (int i = 0; i < 20; i++) {
      const auto data = blob(2048, testing::seed() + uint64_t(i) * 7);
      const Digest32 fp = sha256(sp(data));
      REQUIRE((*s)->chunks().put(fp, sp(data)).ok());
      fps.push_back(fp);
    }
    REQUIRE((*s)->chunks().sync().ok());
  }

  const std::string container = t.path + "/chunks/c00000000.dat";
  for (int trailing : {1, 17, 48, 49, 500, 2000}) {
    TCTX("trailing_garbage=" << trailing);
    // Append a partial record: exactly what kill -9 mid-pwrite leaves behind.
    const std::string cmd = "dd if=/dev/urandom of=" + container + " bs=1 count=" +
                            std::to_string(trailing) +
                            " oflag=append conv=notrunc status=none";
    REQUIRE(shell(cmd));

    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    // Every complete chunk survives...
    CHECK_EQ((*s)->chunks().chunk_count(), fps.size());
    for (const auto& fp : fps) CHECK((*s)->chunks().has(fp));
    // ...and the store verifies clean, i.e. the garbage is gone rather than tolerated.
    auto v = (*s)->verify(true);
    REQUIRE(v.ok());
    CHECK_EQ(v->problems, size_t{0});
  }
}

// Bit rot inside a complete record is a DIFFERENT failure from a torn tail, and the two
// look identical to a sequential scanner. Treating them the same is a data-loss bug:
// truncating at the first bad record silently deletes every valid record after it.
// Measured before the fix: one flipped byte in the first of five records destroyed all
// five, and verify() then reported the store clean because nothing was left to be wrong
// (docs/CHALLENGES.md B4). Recovery now resynchronizes on the record magic instead.
TEST(mid_file_corruption_does_not_discard_the_records_after_it) {
  TempStore t("rot");
  std::vector<Digest32> fps;
  {
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    for (int i = 0; i < 6; i++) {
      const auto data = blob(4000, testing::seed() + uint64_t(i) * 31);
      const Digest32 fp = sha256(sp(data));
      REQUIRE((*s)->chunks().put(fp, sp(data)).ok());
      fps.push_back(fp);
    }
    REQUIRE((*s)->chunks().sync().ok());
  }

  // Corrupt a byte inside the payload of the FIRST record, so five valid records follow.
  const std::string container = t.path + "/chunks/c00000000.dat";
  REQUIRE(shell("printf A | dd of=" + container +
                " bs=1 seek=100 conv=notrunc status=none"));

  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());

  // The damaged chunk is gone -- it is genuinely unreadable, and inventing it is not an
  // option. Everything after it survives.
  CHECK(!(*s)->chunks().has(fps[0]));
  for (size_t i = 1; i < fps.size(); i++) {
    TCTX("chunk=" << i);
    CHECK((*s)->chunks().has(fps[i]));
    auto got = (*s)->chunks().get(fps[i]);
    CHECK(got.ok());
  }
  CHECK_EQ((*s)->chunks().chunk_count(), fps.size() - 1);

  // The damage is reported precisely, not swallowed.
  const auto dmg = (*s)->chunks().damage();
  REQUIRE(dmg.size() == 1);
  CHECK_EQ(dmg[0].offset, uint64_t{0});
  std::printf("    note: damage reported at container=%u offset=%llu length=%llu; "
              "%zu of %zu chunks survived\n",
              dmg[0].container, static_cast<unsigned long long>(dmg[0].offset),
              static_cast<unsigned long long>(dmg[0].length),
              (*s)->chunks().chunk_count(), fps.size());

  // And a store that lost data must NOT verify clean.
  auto v = (*s)->verify(true);
  REQUIRE(v.ok());
  CHECK_GT(v->problems, size_t{0});
}

// Corruption in the LAST record, with nothing valid after it, is indistinguishable from a
// crash mid-append -- and there truncating IS the right answer.
TEST(corruption_in_the_final_record_is_treated_as_a_torn_tail) {
  TempStore t("tailrot");
  std::vector<Digest32> fps;
  uint64_t last_off = 0;
  {
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    for (int i = 0; i < 4; i++) {
      const auto data = blob(3000, testing::seed() + uint64_t(i) * 17);
      const Digest32 fp = sha256(sp(data));
      REQUIRE((*s)->chunks().put(fp, sp(data)).ok());
      fps.push_back(fp);
    }
    REQUIRE((*s)->chunks().sync().ok());
    last_off = 3 * (48 + 3000);
  }
  const std::string container = t.path + "/chunks/c00000000.dat";
  REQUIRE(shell("printf A | dd of=" + container + " bs=1 seek=" +
                std::to_string(last_off + 100) + " conv=notrunc status=none"));

  {
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    for (size_t i = 0; i + 1 < fps.size(); i++) {
      TCTX("chunk=" << i);
      CHECK((*s)->chunks().has(fps[i]));
    }
    CHECK(!(*s)->chunks().has(fps.back()));
    // Truncated, not flagged: a torn tail is the normal shape of kill -9, not a bad disk.
    CHECK((*s)->chunks().damage().empty());
    auto v = (*s)->verify(true);
    REQUIRE(v.ok());
    CHECK_EQ(v->problems, size_t{0});
  }  // the handle must go out of scope first: it holds the flock (SPEC S16)

  // Recovery is idempotent: reopening finds nothing left to do.
  auto s2 = TargetStore::open(t.path);
  REQUIRE(s2.ok());
  CHECK_EQ((*s2)->chunks().chunk_count(), fps.size() - 1);
  CHECK((*s2)->chunks().damage().empty());
}

// ---------------------------------------------------------------------------
// 3. Concurrency (SPEC S8)
// ---------------------------------------------------------------------------

TEST(chunk_store_concurrent_puts_conserve_every_chunk) {
  TempStore t("conc");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  auto& cs = (*s)->chunks();

  constexpr int kThreads = 6;
  constexpr int kPer = 60;
  std::vector<std::vector<Digest32>> produced(kThreads);
  std::vector<std::thread> threads;
  for (int th = 0; th < kThreads; th++) {
    threads.emplace_back([&, th] {
      for (int i = 0; i < kPer; i++) {
        const auto data =
            blob(500 + static_cast<size_t>((th * kPer + i) % 3000),
                 testing::seed() + uint64_t(th) * 1000 + uint64_t(i));
        const Digest32 fp = sha256(sp(data));
        // Half the threads also re-put an overlapping chunk, exercising the benign
        // duplicate-write race described in chunk_store.h.
        if (cs.put(fp, sp(data)).ok()) produced[th].push_back(fp);
        if (th % 2 == 0) (void)cs.put(fp, sp(data));
      }
    });
  }
  for (auto& th : threads) th.join();

  size_t total = 0;
  for (int th = 0; th < kThreads; th++) {
    for (const auto& fp : produced[th]) {
      CHECK(cs.has(fp));
      total++;
    }
  }
  CHECK_EQ(total, size_t{kThreads * kPer});
  auto v = (*s)->verify(true);
  REQUIRE(v.ok());
  CHECK_EQ(v->problems, size_t{0});
  std::printf("    note: %zu chunks stored concurrently by %d threads, verify clean\n",
              cs.chunk_count(), kThreads);
}

// ---------------------------------------------------------------------------
// 4. Generations -- consistency contract C1 (SPEC 3.1, S2)
// ---------------------------------------------------------------------------

TEST(generation_commit_is_idempotent_but_immutable) {
  TempStore t("gen");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  auto& gs = (*s)->generations();

  const auto m0 = blob(500, testing::seed());
  CHECK(gs.commit("backup", 0, sp(m0)).ok());
  // A retry after a lost COMMIT_ACK must succeed (SPEC 3.5).
  CHECK(gs.commit("backup", 0, sp(m0)).ok());

  // But a committed generation is immutable: a different manifest under the same number
  // must be refused, not silently swapped, or C1 would break for anyone who already read it.
  const auto m1 = blob(500, testing::seed() ^ 0xff);
  auto conflict = gs.commit("backup", 0, sp(m1));
  CHECK(!conflict.ok());
  CHECK(conflict.code() == Err::kExists);

  auto back = gs.manifest_bytes("backup", 0);
  REQUIRE(back.ok());
  CHECK(*back == m0);
}

TEST(generation_visibility_is_a_prefix) {
  TempStore t("prefix");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  auto& gs = (*s)->generations();
  for (uint64_t g = 0; g < 6; g++) {
    const auto m = blob(200, testing::seed() + g);
    REQUIRE(gs.commit("ds", g, sp(m)).ok());
  }
  CHECK_EQ(gs.visible_generations("ds").size(), size_t{6});
  CHECK(gs.is_prefix_consistent("ds"));
  auto latest = gs.latest_generation("ds");
  REQUIRE(latest.ok());
  CHECK_EQ(*latest, uint64_t{5});
}

// The core of S2: a manifest on disk that no COMMIT record names does not exist.
TEST(an_uncommitted_manifest_is_invisible_and_swept) {
  TempStore t("orphan");
  std::string orphan;
  {
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    const auto m = blob(300, testing::seed());
    REQUIRE((*s)->generations().commit("ds", 0, sp(m)).ok());
    // Simulate a crash between "manifest durable" and "COMMIT record durable" by writing
    // the manifest for generation 1 and never committing it.
    orphan = (*s)->generations().manifest_path("ds", 1);
    REQUIRE(write_file_atomic(orphan, sp(m)).ok());
    CHECK(path_exists(orphan));
    // Invisible immediately, before any reopen.
    CHECK(!(*s)->generations().is_committed("ds", 1));
    CHECK_EQ((*s)->generations().visible_generations("ds").size(), size_t{1});
  }
  auto s2 = TargetStore::open(t.path);
  REQUIRE(s2.ok());
  CHECK(!path_exists(orphan));  // and swept, so a crashed commit leaves no trace
  CHECK_EQ((*s2)->generations().visible_generations("ds").size(), size_t{1});
  auto v = (*s2)->verify(true);
  REQUIRE(v.ok());
  CHECK_EQ(v->problems, size_t{0});
}

TEST(generation_journal_recovers_from_a_torn_tail) {
  TempStore t("gtorn");
  {
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    for (uint64_t g = 0; g < 4; g++) {
      const auto m = blob(120, testing::seed() + g);
      REQUIRE((*s)->generations().commit("ds", g, sp(m)).ok());
    }
  }
  for (int trailing : {1, 7, 55, 56, 200}) {
    TCTX("trailing=" << trailing);
    const std::string cmd = "dd if=/dev/urandom of=" + t.path + "/GENERATIONS bs=1 count=" +
                            std::to_string(trailing) + " oflag=append conv=notrunc status=none";
    REQUIRE(shell(cmd));
    auto s = TargetStore::open(t.path);
    REQUIRE(s.ok());
    // The four durable generations survive; the garbage does not become a fifth.
    CHECK_EQ((*s)->generations().visible_generations("ds").size(), size_t{4});
    CHECK((*s)->generations().is_prefix_consistent("ds"));
    auto v = (*s)->verify(true);
    REQUIRE(v.ok());
    CHECK_EQ(v->problems, size_t{0});
  }
}

// ---------------------------------------------------------------------------
// 5. Hostile input (SPEC S12)
// ---------------------------------------------------------------------------

// A dataset name becomes a directory name. Every one of these would escape the store root
// or collide with something if it were sanitized instead of refused.
TEST(hostile_dataset_names_are_refused) {
  TempStore t("hostile");
  auto s = TargetStore::open(t.path);
  REQUIRE(s.ok());
  auto& gs = (*s)->generations();
  const auto m = blob(64, testing::seed());

  const char* bad[] = {"..",       "../escape", "/absolute", "a/b",   "",
                       ".hidden",  "with space", "semi;colon", "nul\x01", "tilde~",
                       "dollar$",  "back\\slash"};
  for (const char* name : bad) {
    TCTX("name='" << name << "'");
    auto r = gs.commit(name, 0, sp(m));
    CHECK(!r.ok());
    CHECK(r.code() == Err::kInvalidArgument);
  }
  // A very long name is also refused rather than truncated.
  auto r = gs.commit(std::string(200, 'a'), 0, sp(m));
  CHECK(!r.ok());

  const char* good[] = {"backup", "prod-2026", "a_b.c", "X"};
  for (const char* name : good) {
    TCTX("name='" << name << "'");
    CHECK(gs.commit(name, 0, sp(m)).ok());
  }
}

// ---------------------------------------------------------------------------
// 6. The open-time gates (SPEC S16, CHALLENGES B2)
// ---------------------------------------------------------------------------

TEST(a_second_process_cannot_open_the_same_store) {
  TempStore t("lock");
  auto first = TargetStore::open(t.path);
  REQUIRE(first.ok());
  auto second = TargetStore::open(t.path);
  CHECK(!second.ok());
  CHECK(second.code() == Err::kLocked);
  // ...and the lock is released when the first handle goes away.
  first = err(Err::kCancelled, "drop");
  auto third = TargetStore::open(t.path);
  CHECK(third.ok());
}

// The B2 guard. On a filesystem where flock does not exclude, opening a store is refused
// outright -- turning a silent corruption into a startup error that names its own cause.
TEST(a_store_is_refused_where_flock_does_not_exclude) {
  const char* candidates[] = {"/work/scratch/out", "/work"};
  bool tested = false;
  for (const char* base : candidates) {
    if (!path_exists(base)) continue;
    std::string detail;
    if (probe_flock_exclusion(base, &detail) != FlockSupport::kNotExclusive) continue;
    const std::string path = std::string(base) + "/wanrep_guard_test";
    discard(shell("rm -rf " + path));
    auto s = TargetStore::open(path);
    CHECK(!s.ok());
    CHECK(s.code() == Err::kUnsafeFilesystem);
    std::printf("    note: %s -> refused: %.90s...\n", base, s.error().message().c_str());
    // The documented escape hatch still works, for read-only inspection.
    TargetStoreOptions opt;
    opt.allow_unsafe_filesystem = true;
    auto forced = TargetStore::open(path, opt);
    CHECK(forced.ok());
    forced = err(Err::kCancelled, "drop");
    discard(shell("rm -rf " + path));
    tested = true;
    break;
  }
  if (!tested) {
    std::printf("    note: no unsafe filesystem visible here; guard not exercised\n");
  }
}

TEST(a_foreign_directory_is_not_mistaken_for_a_store) {
  TempStore t("foreign");
  REQUIRE(make_dirs(t.path).ok());
  const auto junk = blob(64, testing::seed());
  REQUIRE(write_file_atomic(t.path + "/TARGET", sp(junk)).ok());
  auto s = TargetStore::open(t.path);
  CHECK(!s.ok());
  CHECK(s.code() == Err::kCorrupt);
}

RUN_ALL()
