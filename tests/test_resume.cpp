// T9: resumable transfers (SPEC 3.7, R2.4, R2.5, S5, S6).
//
// The project claims a replication job "recovered cleanly from a dropped connection rather
// than restarting from the beginning". That is two claims, and they need different tests:
//   * CLEANLY -- the target is still correct afterwards, checked by the same oracle every
//     other failure test uses.
//   * RATHER THAN RESTARTING -- the bytes re-sent are bounded and small, MEASURED on the
//     wire rather than argued from the design.
//
// The most important test here is the last one: it deletes the session file before
// reconnecting, and still asserts almost nothing is re-sent. That is the difference
// between resume being a bookkeeping feature and resume being a property of content
// addressing (SPEC 3.0).
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "test.h"
#include "wanrep/fault_link.h"
#include "wanrep/protocol.h"

using namespace wanrep;

namespace {

inline void discard(bool) {}
bool shell(const std::string& cmd) { return std::system(cmd.c_str()) == 0; }

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

struct TempDir {
  std::string path;
  explicit TempDir(const char* tag) {
    static std::atomic<int> n{0};
    path = std::string("/tmp/wanrep_res_") + tag + "_" + std::to_string(n.fetch_add(1)) +
           "_" + std::to_string(::getpid());
    discard(shell("rm -rf " + path));
    discard(make_dirs(path).ok());
  }
  ~TempDir() { discard(shell("rm -rf " + path)); }
};

std::vector<uint8_t> random_blob(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(rng.next() >> 24);
  return v;
}

bool put_file(const std::string& path, const std::vector<uint8_t>& data) {
  return make_dirs(dirname_of(path)).ok() &&
         write_file_atomic(path, ByteSpan(data.data(), data.size())).ok();
}

// Spawns a fresh target thread per connection, exactly as a daemon would accept a new
// socket after the previous one broke.
class TargetHarness {
 public:
  TargetHarness(TargetStore& store, SessionJournal& sessions)
      : store_(store), sessions_(sessions) {}
  ~TargetHarness() { join(); }

  // Returns the SOURCE side of a new connection.
  //
  // The pair is given a 128 KiB in-flight capacity so it behaves like a socket with real
  // buffers. Without that bound the source races arbitrarily far ahead of the target, and
  // an injected drop then discards a backlog that no real connection would have been
  // holding -- which understates how much of the transfer actually landed and makes
  // resume look far worse than it is.
  std::shared_ptr<Link> connect() {
    auto [a, b] = MemoryLink::make_pair(0, 128 * 1024);
    threads_.emplace_back([this, b] {
      TargetServer server(store_, sessions_);
      auto r = server.serve(*b);
      if (!r.ok()) failures_.fetch_add(1, std::memory_order_relaxed);
      b->close();
    });
    return a;
  }

  void join() {
    for (auto& t : threads_) {
      if (t.joinable()) t.join();
    }
    threads_.clear();
  }
  int failures() const { return failures_.load(std::memory_order_relaxed); }

 private:
  TargetStore& store_;
  SessionJournal& sessions_;
  std::vector<std::thread> threads_;
  std::atomic<int> failures_{0};
};

struct Fixture {
  TempDir tree{"tree"};
  TempDir store_dir{"store"};
  std::unique_ptr<TargetStore> store;
  std::unique_ptr<SessionJournal> sessions;

  bool init(size_t bytes, uint64_t seed) {
    // Several files so the transfer spans many batches and a drop can land mid-stream.
    if (!put_file(tree.path + "/a.bin", random_blob(bytes / 2, seed))) return false;
    if (!put_file(tree.path + "/b/c.bin", random_blob(bytes / 3, seed + 1))) return false;
    if (!put_file(tree.path + "/b/d.bin", random_blob(bytes / 6, seed + 2))) return false;
    auto s = TargetStore::open(store_dir.path);
    if (!s.ok()) return false;
    store = std::move(*s);
    auto j = SessionJournal::open(store_dir.path);
    if (!j.ok()) return false;
    sessions = std::move(*j);
    return true;
  }

  bool materializes_correctly(uint64_t generation) {
    auto mb = store->generations().manifest_bytes("ds", generation);
    if (!mb.ok()) return false;
    auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
    if (!m.ok()) return false;
    const std::string out = store_dir.path + "/materialized";
    discard(shell("rm -rf " + out));
    if (!materialize(*m, store->chunks(), out).ok()) return false;
    return shell("diff -r " + tree.path + " " + out + " >/dev/null");
  }
};

// A clean run, for the baseline the re-send bound is measured against.
uint64_t clean_run_wire_bytes(const std::string& tree, uint64_t seed) {
  TempDir sd("baseline");
  auto store = TargetStore::open(sd.path);
  if (!store.ok()) return 0;
  auto sessions = SessionJournal::open(sd.path);
  if (!sessions.ok()) return 0;
  TargetHarness h(**store, **sessions);
  auto link = h.connect();
  SourceJob::Options opt;
  opt.dataset = "ds";
  auto r = SourceJob::run(*link, tree, opt);
  link->close();
  h.join();
  (void)seed;
  return r.ok() ? r->wire_bytes_out : 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. A dropped link resumes rather than restarting (R2.4)
// ---------------------------------------------------------------------------

TEST(a_dropped_link_resumes_and_re_sends_only_a_bounded_amount) {
  Fixture f;
  REQUIRE(f.init(3000000, testing::seed()));
  const uint64_t baseline = clean_run_wire_bytes(f.tree.path, testing::seed());
  REQUIRE(baseline > 500000);

  TargetHarness h(*f.store, *f.sessions);
  auto scanned = scan_tree(f.tree.path, "ds", 0);
  REQUIRE(scanned.ok());

  // Attempt 1: drop partway through the payload phase.
  std::string session_id;
  uint64_t attempt1_out = 0;
  {
    auto inner = h.connect();
    auto faulty = std::make_shared<FaultLink>(inner, nullptr, FaultPoint::kMidPayloadEarly);
    faulty->set_drop_after_bytes(baseline / 2);  // roughly halfway
    SourceJob::Options opt;
    opt.dataset = "ds";
    auto r = SourceJob::run(*faulty, f.tree.path, opt, &*scanned, &session_id);
    CHECK(!r.ok());  // the drop must surface as a failure, not a silent success
    attempt1_out = faulty->bytes_out();
    inner->close();
  }
  REQUIRE(!session_id.empty());
  CHECK(!f.store->generations().is_committed("ds", 0));  // nothing committed yet (C1)

  // Attempt 2: reconnect and resume.
  uint64_t attempt2_out = 0;
  {
    auto link = h.connect();
    SourceJob::Options opt;
    opt.dataset = "ds";
    opt.resume_session_id = session_id;
    auto r = SourceJob::run(*link, f.tree.path, opt, &*scanned);
    REQUIRE(r.ok());
    CHECK(r->resumed);
    // The resume point is derived from what the target actually holds, so it reflects the
    // real progress of the dropped attempt rather than the last 8 MiB checkpoint boundary
    // (CHALLENGES B7). A transfer smaller than one checkpoint interval must still resume.
    CHECK_GT(r->resumed_from, uint64_t{0});
    attempt2_out = link->bytes_out();
    link->close();
  }
  h.join();

  const uint64_t total = attempt1_out + attempt2_out;
  const double overhead = 100.0 * (static_cast<double>(total) / static_cast<double>(baseline) - 1.0);
  std::printf("    note: clean run %llu B; dropped run %llu + %llu = %llu B "
              "(%.1f%% overhead vs a restart's 100%%)\n",
              static_cast<unsigned long long>(baseline),
              static_cast<unsigned long long>(attempt1_out),
              static_cast<unsigned long long>(attempt2_out),
              static_cast<unsigned long long>(total), overhead);

  // "Rather than restarting from the beginning": a restart would cost ~2x the baseline.
  CHECK_LT(total, baseline * 3 / 2);
  CHECK(f.store->generations().is_committed("ds", 0));
  CHECK(f.materializes_correctly(0));
  auto v = f.store->verify(true);
  REQUIRE(v.ok());
  CHECK_EQ(v->problems, size_t{0});
}

// The same thing, at many randomized drop offsets -- because a resume that works at one
// offset and not another is a resume that does not work (SPEC S15: seeded and replayable).
TEST(resume_is_correct_at_many_drop_offsets) {
  const uint64_t base_seed = testing::seed();
  for (int trial = 0; trial < 6; trial++) {
    TCTX("trial=" << trial);
    Fixture f;
    REQUIRE(f.init(1200000, base_seed + static_cast<uint64_t>(trial)));
    Rng rng(base_seed ^ (0x51ed * (static_cast<uint64_t>(trial) + 1)));
    const uint64_t baseline = clean_run_wire_bytes(f.tree.path, base_seed);
    REQUIRE(baseline > 100000);
    const uint64_t drop_at = 20000 + (rng.next() % (baseline - 40000));

    TargetHarness h(*f.store, *f.sessions);
    auto scanned = scan_tree(f.tree.path, "ds", 0);
    REQUIRE(scanned.ok());

    std::string session_id;
    {
      auto inner = h.connect();
      auto faulty = std::make_shared<FaultLink>(inner, nullptr, FaultPoint::kMidPayloadLate);
      faulty->set_drop_after_bytes(drop_at);
      SourceJob::Options opt;
      opt.dataset = "ds";
      auto r = SourceJob::run(*faulty, f.tree.path, opt, &*scanned, &session_id);
      (void)r;  // may fail at any phase, including before a session exists
      inner->close();
    }

    // Whatever happened, finish the job. Either resume or a fresh negotiation is legal;
    // what matters is that it completes and the result is correct.
    SourceJob::Options opt;
    opt.dataset = "ds";
    opt.resume_session_id = session_id;
    auto link = h.connect();
    auto r = SourceJob::run(*link, f.tree.path, opt, &*scanned);
    if (!r.ok() && r.error().code == Err::kNotFound) {
      link->close();
      opt.resume_session_id.clear();
      auto link2 = h.connect();
      r = SourceJob::run(*link2, f.tree.path, opt, &*scanned);
      link2->close();
    } else {
      link->close();
    }
    h.join();

    REQUIRE(r.ok());
    CHECK(f.store->generations().is_committed("ds", 0));
    CHECK(f.materializes_correctly(0));
    auto v = f.store->verify(true);
    REQUIRE(v.ok());
    CHECK_EQ(v->problems, size_t{0});
  }
}

// ---------------------------------------------------------------------------
// 2. run_resilient: the whole thing as one call (R2.4)
// ---------------------------------------------------------------------------

TEST(run_resilient_survives_repeated_drops) {
  Fixture f;
  REQUIRE(f.init(2000000, testing::seed()));
  TargetHarness h(*f.store, *f.sessions);

  std::atomic<int> attempt{0};
  const uint64_t baseline = clean_run_wire_bytes(f.tree.path, testing::seed());
  REQUIRE(baseline > 100000);

  SourceJob::LinkFactory factory = [&]() -> Result<std::shared_ptr<Link>> {
    const int n = attempt.fetch_add(1);
    auto inner = h.connect();
    if (n < 3) {  // the first three connections die partway through
      auto faulty = std::make_shared<FaultLink>(inner, nullptr, FaultPoint::kMidPayloadEarly);
      faulty->set_drop_after_bytes(baseline / 4 + static_cast<uint64_t>(n) * 50000);
      return std::static_pointer_cast<Link>(faulty);
    }
    return std::static_pointer_cast<Link>(inner);
  };

  SourceJob::Options opt;
  opt.dataset = "ds";
  int used = 0;
  auto r = SourceJob::run_resilient(factory, f.tree.path, opt, 8, &used);
  h.join();

  REQUIRE(r.ok());
  std::printf("    note: completed after %d attempts; %llu total wire bytes vs %llu clean "
              "(%.2fx)\n",
              used, static_cast<unsigned long long>(r->wire_bytes_out),
              static_cast<unsigned long long>(baseline),
              static_cast<double>(r->wire_bytes_out) / static_cast<double>(baseline));
  CHECK_GT(used, 1);
  CHECK(f.store->generations().is_committed("ds", 0));
  CHECK(f.materializes_correctly(0));
  // Three failures must not cost anything like four full transfers.
  CHECK_LT(r->wire_bytes_out, baseline * 5 / 2);
}

// ---------------------------------------------------------------------------
// 3. THE test: losing the checkpoint entirely is still not a restart (S6)
// ---------------------------------------------------------------------------
//
// This is the claim from SPEC 3.0 that resume is a property of content addressing rather
// than of bookkeeping. Delete every trace of the session, then reconnect: the target must
// still not ask for the chunks it already holds.
TEST(deleting_the_session_file_still_does_not_cause_a_restart) {
  Fixture f;
  REQUIRE(f.init(3000000, testing::seed()));
  const uint64_t baseline = clean_run_wire_bytes(f.tree.path, testing::seed());
  REQUIRE(baseline > 500000);

  TargetHarness h(*f.store, *f.sessions);
  auto scanned = scan_tree(f.tree.path, "ds", 0);
  REQUIRE(scanned.ok());

  std::string session_id;
  uint64_t attempt1_out = 0;
  {
    auto inner = h.connect();
    auto faulty = std::make_shared<FaultLink>(inner, nullptr, FaultPoint::kMidPayloadEarly);
    faulty->set_drop_after_bytes(baseline * 2 / 3);
    SourceJob::Options opt;
    opt.dataset = "ds";
    auto r = SourceJob::run(*faulty, f.tree.path, opt, &*scanned, &session_id);
    CHECK(!r.ok());
    attempt1_out = faulty->bytes_out();
    inner->close();
  }
  REQUIRE(!session_id.empty());

  // Nuke the entire sessions directory: checkpoint, manifest blob, need blob.
  REQUIRE(shell("rm -rf " + f.store_dir.path + "/sessions"));
  auto reopened = SessionJournal::open(f.store_dir.path);
  REQUIRE(reopened.ok());
  TargetHarness h2(*f.store, **reopened);

  // Fresh negotiation -- there is nothing to resume from.
  uint64_t attempt2_out = 0;
  {
    auto link = h2.connect();
    SourceJob::Options opt;
    opt.dataset = "ds";
    auto r = SourceJob::run(*link, f.tree.path, opt, &*scanned);
    REQUIRE(r.ok());
    CHECK(!r->resumed);  // it did NOT take the fast path...
    // ...and yet it skipped everything already stored, because the set difference is
    // computed from what the target HAS, not from what it remembers being told.
    CHECK_GT(r->chunks_skipped, size_t{0});
    attempt2_out = link->bytes_out();
    std::printf("    note: session deleted -> fresh negotiation skipped %zu of %zu chunks; "
                "second attempt sent %llu B (%.0f%% of a full transfer)\n",
                r->chunks_skipped, r->chunks_total,
                static_cast<unsigned long long>(attempt2_out),
                100.0 * static_cast<double>(attempt2_out) / static_cast<double>(baseline));
    link->close();
  }
  h.join();
  h2.join();

  // A true restart would have re-sent everything: attempt2 alone would be ~baseline.
  CHECK_LT(attempt2_out, baseline * 3 / 5);
  CHECK_LT(attempt1_out + attempt2_out, baseline * 3 / 2);
  CHECK(f.store->generations().is_committed("ds", 0));
  CHECK(f.materializes_correctly(0));
}

// ---------------------------------------------------------------------------
// 4. Commit is idempotent across a drop between commit and ack (S5)
// ---------------------------------------------------------------------------

TEST(a_drop_between_commit_and_ack_is_recoverable) {
  Fixture f;
  REQUIRE(f.init(400000, testing::seed()));
  auto scanned = scan_tree(f.tree.path, "ds", 0);
  REQUIRE(scanned.ok());

  global_faults().clear();
  global_faults().arm(FaultPoint::kAfterCommitBeforeAck, FaultKind::kDropLink);
  {
    TargetHarness h(*f.store, *f.sessions);
    auto link = h.connect();
    SourceJob::Options opt;
    opt.dataset = "ds";
    auto r = SourceJob::run(*link, f.tree.path, opt, &*scanned);
    CHECK(!r.ok());  // the source never saw its COMMIT_ACK
    link->close();
    h.join();
  }
  global_faults().clear();

  // The target DID commit. The generation is visible and correct even though the source
  // believes the job failed -- and a retry must succeed rather than conflict.
  CHECK(f.store->generations().is_committed("ds", 0));
  CHECK(f.materializes_correctly(0));

  {
    TargetHarness h(*f.store, *f.sessions);
    auto link = h.connect();
    SourceJob::Options opt;
    opt.dataset = "ds";
    auto r = SourceJob::run(*link, f.tree.path, opt, &*scanned);
    REQUIRE(r.ok());  // idempotent: the retry commits the same generation again, cleanly
    link->close();
    h.join();
  }
  auto v = f.store->verify(true);
  REQUIRE(v.ok());
  CHECK_EQ(v->problems, size_t{0});
  std::printf("    note: drop between commit and ack -> generation committed, retry clean\n");
}

RUN_ALL()
