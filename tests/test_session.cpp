// T9 core: the contiguous high-water mark and the durable session checkpoint
// (SPEC 3.7, S5, S6, S10, S12).
//
// The tracker is the piece where a subtle bug is most expensive: it decides where a
// resumed transfer restarts. If it ever reported a mark ABOVE a gap, the resume would
// skip a chunk that never arrived and the transfer would report success with data
// missing. So the property tests below hammer it with out-of-order, duplicate and
// adversarial sequences rather than checking a few examples.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include "test.h"
#include "wanrep/session.h"

using namespace wanrep;

namespace {

inline void discard(bool) {}
bool shell(const std::string& cmd) { return std::system(cmd.c_str()) == 0; }

struct TempDir {
  std::string path;
  explicit TempDir(const char* tag) {
    static std::atomic<int> n{0};
    path = std::string("/tmp/wanrep_ses_") + tag + "_" + std::to_string(n.fetch_add(1)) +
           "_" + std::to_string(::getpid());
    discard(shell("rm -rf " + path));
    discard(make_dirs(path).ok());
  }
  ~TempDir() { discard(shell("rm -rf " + path)); }
};

}  // namespace

// ---------------------------------------------------------------------------
// 1. The contiguous high-water mark
// ---------------------------------------------------------------------------

TEST(tracker_advances_only_over_contiguous_ranges) {
  HighWaterTracker t(100);
  CHECK_EQ(t.contiguous(), uint64_t{0});
  CHECK(t.mark_range(0, 10).ok());
  CHECK_EQ(t.contiguous(), uint64_t{10});

  // A gap: 20..30 arrives before 10..20. The mark must NOT jump -- this is the whole
  // reason it is "contiguous" and not "highest seen".
  CHECK(t.mark_range(20, 10).ok());
  CHECK_EQ(t.contiguous(), uint64_t{10});

  CHECK(t.mark_range(10, 10).ok());  // the gap fills
  CHECK_EQ(t.contiguous(), uint64_t{30});
}

TEST(tracker_treats_duplicates_as_idempotent) {
  HighWaterTracker t(50);
  CHECK(t.mark_range(0, 20).ok());
  CHECK_EQ(t.contiguous(), uint64_t{20});
  // A resumed transfer re-sends its in-flight window (SPEC 3.7). Re-marking must be a
  // no-op, never an error and never a double-advance.
  CHECK(t.mark_range(0, 20).ok());
  CHECK(t.mark_range(5, 3).ok());
  CHECK_EQ(t.contiguous(), uint64_t{20});
  CHECK(t.mark_range(20, 30).ok());
  CHECK_EQ(t.contiguous(), uint64_t{50});
  CHECK(t.complete());
}

TEST(tracker_rejects_ranges_outside_the_plan) {
  HighWaterTracker t(100);
  CHECK(!t.mark_range(95, 10).ok());        // runs past the end
  CHECK(!t.mark_range(101, 1).ok());
  CHECK(!t.mark_range(0, 101).ok());
  // Overflow attempt: seq + count must not wrap.
  CHECK(!t.mark_range(~uint64_t{0} - 1, 5).ok());
  CHECK_EQ(t.contiguous(), uint64_t{0});
}

// SPEC S10: a peer that sends far ahead must be refused rather than allowed to grow
// receive-side memory. The window is the bound.
TEST(tracker_rejects_sequences_beyond_the_reorder_window) {
  HighWaterTracker t(kOutOfOrderWindow * 4);
  CHECK(t.mark_range(0, 1).ok());
  CHECK(t.mark_range(kOutOfOrderWindow - 1, 1).ok());   // just inside
  auto r = t.mark_range(kOutOfOrderWindow + 1, 1);      // beyond
  CHECK(!r.ok());
  CHECK(r.code() == Err::kProtocol);
}

// The property test: whatever order the ranges arrive in, the mark must equal the length
// of the longest prefix actually received. Compared against a dumb reference oracle.
TEST(tracker_matches_a_reference_oracle_under_random_orderings) {
  for (int trial = 0; trial < 200; trial++) {
    TCTX("trial=" << trial);
    std::mt19937_64 rng(testing::seed() + static_cast<uint64_t>(trial));
    const uint64_t n = 1 + (rng() % 2000);
    // Split [0,n) into contiguous ranges, then deliver them shuffled.
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    uint64_t at = 0;
    while (at < n) {
      const uint64_t len = std::min<uint64_t>(1 + (rng() % 37), n - at);
      ranges.push_back({at, len});
      at += len;
    }
    std::shuffle(ranges.begin(), ranges.end(), rng);

    HighWaterTracker t(n);
    std::vector<char> got(n, 0);  // the oracle
    for (const auto& [seq, len] : ranges) {
      REQUIRE(t.mark_range(seq, len).ok());
      for (uint64_t i = 0; i < len; i++) got[seq + i] = 1;
      uint64_t expect = 0;
      while (expect < n && got[expect]) expect++;
      CHECK_EQ(t.contiguous(), expect);
    }
    CHECK(t.complete());
  }
}

TEST(tracker_resumes_from_a_nonzero_base) {
  // After a reconnect the target rebuilds its tracker at the durable mark.
  HighWaterTracker t(1000, /*base=*/400);
  CHECK_EQ(t.contiguous(), uint64_t{400});
  // The source re-sends its in-flight window from 400; those are duplicates below base.
  CHECK(t.mark_range(390, 20).ok());
  CHECK_EQ(t.contiguous(), uint64_t{410});
  CHECK(t.mark_range(410, 590).ok());
  CHECK(t.complete());
}

TEST(tracker_window_slides_across_many_words) {
  // Exercises the word-level shift across word boundaries and multi-word moves.
  HighWaterTracker t(kOutOfOrderWindow * 8);
  uint64_t at = 0;
  for (int i = 0; i < 400; i++) {
    const uint64_t len = 1 + static_cast<uint64_t>(i % 130);
    REQUIRE(t.mark_range(at, len).ok());
    at += len;
    CHECK_EQ(t.contiguous(), at);
  }
  std::printf("    note: slid the window over %llu indices in %d marks\n",
              static_cast<unsigned long long>(at), 400);
}

// ---------------------------------------------------------------------------
// 2. The durable checkpoint
// ---------------------------------------------------------------------------

TEST(session_checkpoint_round_trips) {
  TempDir d("rt");
  auto j = SessionJournal::open(d.path);
  REQUIRE(j.ok());

  SessionState st;
  st.dataset = "backup";
  st.generation = 7;
  st.manifest_digest = sha256(as_bytes(std::string_view("manifest")));
  st.session_id = SessionJournal::session_id_for(st.dataset, st.generation, st.manifest_digest);
  st.plan_size = 123456;
  st.high_water = 60000;
  st.bytes_received = 987654321;

  REQUIRE((*j)->save(st).ok());
  auto back = (*j)->load(st.session_id);
  REQUIRE(back.ok());
  CHECK_EQ(back->dataset, st.dataset);
  CHECK_EQ(back->generation, st.generation);
  CHECK_EQ(back->plan_size, st.plan_size);
  CHECK_EQ(back->high_water, st.high_water);
  CHECK_EQ(back->bytes_received, st.bytes_received);
  CHECK(back->manifest_digest == st.manifest_digest);
  CHECK_EQ(back->session_id, st.session_id);
}

// Deterministic ids mean a source that forgot the id it was given can recompute it, so
// the id itself never has to be durable on the source side.
TEST(session_ids_are_deterministic_and_distinguish_jobs) {
  const Digest32 a = sha256(as_bytes(std::string_view("m-a")));
  const Digest32 b = sha256(as_bytes(std::string_view("m-b")));
  const std::string id1 = SessionJournal::session_id_for("ds", 1, a);
  CHECK_EQ(id1, SessionJournal::session_id_for("ds", 1, a));
  CHECK_NE(id1, SessionJournal::session_id_for("ds", 2, a));   // generation matters
  CHECK_NE(id1, SessionJournal::session_id_for("other", 1, a));  // dataset matters
  CHECK_NE(id1, SessionJournal::session_id_for("ds", 1, b));   // manifest matters
  CHECK(SessionJournal::valid_session_id(id1));
  CHECK_EQ(id1.size(), size_t{32});
}

TEST(a_missing_session_is_not_found_not_an_error_to_panic_about) {
  TempDir d("miss");
  auto j = SessionJournal::open(d.path);
  REQUIRE(j.ok());
  auto r = (*j)->load("00112233445566778899aabbccddeeff");
  CHECK(!r.ok());
  CHECK(r.code() == Err::kNotFound);
}

// SPEC S12: a session id arrives from the peer and becomes a filename.
TEST(hostile_session_ids_are_refused) {
  TempDir d("hostile");
  auto j = SessionJournal::open(d.path);
  REQUIRE(j.ok());
  const char* bad[] = {"../escape", "/abs", "a/b", "", "UPPER", "with space",
                       "semi;colon", "dot.dot", "zzz"};
  for (const char* id : bad) {
    TCTX("id='" << id << "'");
    CHECK(!SessionJournal::valid_session_id(id));
    auto r = (*j)->load(id);
    CHECK(!r.ok());
    CHECK(r.code() == Err::kInvalidArgument);
  }
}

// A corrupt checkpoint must degrade to "re-negotiate", never to a wrong resume point.
TEST(a_corrupt_checkpoint_is_rejected_rather_than_trusted) {
  TempDir d("corrupt");
  auto j = SessionJournal::open(d.path);
  REQUIRE(j.ok());
  SessionState st;
  st.dataset = "ds";
  st.generation = 1;
  st.manifest_digest = sha256(as_bytes(std::string_view("m")));
  st.session_id = SessionJournal::session_id_for(st.dataset, st.generation, st.manifest_digest);
  st.plan_size = 1000;
  st.high_water = 500;
  REQUIRE((*j)->save(st).ok());

  const std::string p = d.path + "/sessions/" + st.session_id + ".ses";
  for (int byte = 0; byte < 20; byte++) {
    TCTX("flip_byte=" << byte);
    REQUIRE((*j)->save(st).ok());  // restore a good copy first
    REQUIRE(shell("printf '\\001' | dd of=" + p + " bs=1 seek=" + std::to_string(byte) +
                  " conv=notrunc status=none"));
    auto r = (*j)->load(st.session_id);
    // Either the CRC catches it, or (if the flip landed on a field the CRC also covers)
    // it is still caught. What must never happen is a silently different resume point.
    if (r.ok()) {
      CHECK_EQ(r->high_water, st.high_water);
      CHECK_EQ(r->plan_size, st.plan_size);
    } else {
      CHECK(r.code() == Err::kCorrupt || r.code() == Err::kBadMagic ||
            r.code() == Err::kMalformed);
    }
  }
}

// A checkpoint claiming a mark past the end of the plan would let a resume skip chunks
// that never arrived -- the one corruption that could cause silent data loss.
TEST(a_checkpoint_with_a_high_water_past_the_plan_is_refused) {
  TempDir d("past");
  auto j = SessionJournal::open(d.path);
  REQUIRE(j.ok());
  SessionState st;
  st.dataset = "ds";
  st.generation = 1;
  st.manifest_digest = sha256(as_bytes(std::string_view("m")));
  st.session_id = SessionJournal::session_id_for(st.dataset, st.generation, st.manifest_digest);
  st.plan_size = 100;
  st.high_water = 1000;  // impossible
  REQUIRE((*j)->save(st).ok());
  auto r = (*j)->load(st.session_id);
  CHECK(!r.ok());
  CHECK(r.code() == Err::kMalformed);
}

// The claim from SPEC 3.7 that matters most: losing the checkpoint entirely is SAFE.
TEST(losing_the_checkpoint_is_recoverable_not_fatal) {
  TempDir d("lost");
  auto j = SessionJournal::open(d.path);
  REQUIRE(j.ok());
  SessionState st;
  st.dataset = "ds";
  st.generation = 3;
  st.manifest_digest = sha256(as_bytes(std::string_view("m")));
  st.session_id = SessionJournal::session_id_for(st.dataset, st.generation, st.manifest_digest);
  st.plan_size = 500;
  st.high_water = 250;
  REQUIRE((*j)->save(st).ok());
  REQUIRE((*j)->erase(st.session_id).ok());

  auto r = (*j)->load(st.session_id);
  CHECK(!r.ok());
  CHECK(r.code() == Err::kNotFound);
  // kNotFound is the signal to re-negotiate (SPEC 3.7 fallback path) -- a recoverable
  // state, deliberately distinct from kCorrupt and from a hard failure. The chunks
  // already stored are still there; only two round trips are lost.
  CHECK(r.code() != Err::kCorrupt);
}

RUN_ALL()
