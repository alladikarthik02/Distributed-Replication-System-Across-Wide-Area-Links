// T4: the lock-free queues (SPEC 3.6, R2.1, S9).
//
// The test that matters here is not any of the single-threaded ones -- it is
// *_conserves_every_item. A concurrent queue that is subtly wrong does not crash and does
// not usually lose an item on the run you are watching; it loses one item in ten million
// on a machine you do not own. So the stress tests do not assert a COUNT (a count is
// blind to "lost one, duplicated another") -- they assert IDENTITY: every produced tag is
// marked in a bitmap exactly once, and a value-sensitive checksum over the tags is
// reproduced exactly. Nothing lost, nothing duplicated, nothing torn.
//
// The other deliberate choice: the queues are also tested against a std::deque reference
// model under a seeded random interleaving of pushes and pops. Hand-written example tests
// only find the cases you already thought of; a differential model finds the boundary you
// did not (the lap where head wraps and tail has not, the pop that empties a full ring).
//
// The cache-line tests exist because that padding has NO behavioural signature. If the
// alignas silently stopped working the queues would still be correct and would simply run
// several times slower under contention -- and nothing would ever fail. So it is asserted.
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "test.h"
#include "wanrep/mpmc_queue.h"
#include "wanrep/spsc_ring.h"

using namespace wanrep;

namespace {

// Deterministic PRNG, same one the rest of the suite uses. Seeded from testing::seed()
// so any failure replays with WANREP_SEED (SPEC S15).
struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 0x123456789abcdefull) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
  uint64_t below(uint64_t n) { return next() % n; }
};

// A value-sensitive mixer for the conservation checksum. A plain XOR of raw tags would be
// fooled by swapping two items' bits between them; mixing first means any change to the
// multiset of delivered values changes the accumulator.
uint64_t mix(uint64_t x) {
  x += 0x9E3779B97F4A7C15ull;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
  return x ^ (x >> 31);
}

// ---------------------------------------------------------------------------
// Move-only payloads
// ---------------------------------------------------------------------------
//
// The pipeline moves buffers (SPEC 3.6). A queue that copied a std::vector payload per
// hop would cost more than the work it exists to overlap, so "move-only survives this
// queue" is a requirement, not a nicety.
//
// Tracked deletes its copy operations, so ANY copy the queue tried to make would be a
// COMPILE error rather than a silent performance bug -- that is the strongest form this
// assertion can take. It also keeps a net live-object count, which catches the two
// failures a tag bitmap cannot see: a slot destroyed twice, or a slot never destroyed.
std::atomic<int64_t>& tracked_live() {
  static std::atomic<int64_t> n{0};
  return n;
}

struct Tracked {
  uint64_t tag;
  bool armed;  // owns a "live" count; cleared when moved from

  // No default constructor on purpose: the queues store into raw storage precisely so a
  // pipeline item is never forced to invent an empty state. try_pop's out-parameter still
  // needs one object to assign into, which is why the tests declare `Tracked out(0)`.
  explicit Tracked(uint64_t t) : tag(t), armed(true) {
    tracked_live().fetch_add(1, std::memory_order_relaxed);
  }
  Tracked(const Tracked&) = delete;
  Tracked& operator=(const Tracked&) = delete;
  Tracked(Tracked&& o) noexcept : tag(o.tag), armed(o.armed) { o.armed = false; }
  Tracked& operator=(Tracked&& o) noexcept {
    if (this != &o) {
      if (armed) tracked_live().fetch_sub(1, std::memory_order_relaxed);
      tag = o.tag;
      armed = o.armed;
      o.armed = false;
    }
    return *this;
  }
  ~Tracked() {
    if (armed) tracked_live().fetch_sub(1, std::memory_order_relaxed);
  }
};

// ---------------------------------------------------------------------------
// The differential model: a bounded std::deque
// ---------------------------------------------------------------------------
template <class Q>
void model_check(Q& q, size_t cap, uint64_t seed, size_t ops) {
  Rng rng(seed);
  std::deque<uint64_t> model;
  uint64_t next_value = 1;

  for (size_t i = 0; i < ops; i++) {
    TCTX("op=" << i << " model_size=" << model.size() << " cap=" << cap);
    // Biased towards pushing so the queue actually spends time full; a 50/50 mix hovers
    // around half depth and never exercises the wrap-with-full-ring case.
    if (rng.below(100) < 60) {
      const uint64_t v = next_value++;
      const bool pushed = q.try_push(uint64_t{v});
      CHECK_EQ(pushed, model.size() < cap);
      if (pushed) model.push_back(v);
    } else {
      uint64_t got = 0;
      const bool popped = q.try_pop(got);
      CHECK_EQ(popped, !model.empty());
      if (popped) {
        CHECK_EQ(got, model.front());  // FIFO, and the exact value
        model.pop_front();
      }
    }
  }
  std::printf("    note: model check ok, %zu ops, final depth %zu / %zu\n", ops,
              model.size(), cap);
}

// ---------------------------------------------------------------------------
// The item-conservation stress harness (SPEC S9)
// ---------------------------------------------------------------------------
struct StressStats {
  uint64_t full_hits = 0;   // try_push returned false: backpressure was really exercised
  uint64_t empty_hits = 0;  // try_pop returned false: the consumers really outran producers
};

// Producers push tags [0, producers*per_producer). Consumers pop until that many items
// have been taken in total. Afterwards every tag must appear in the merged output exactly
// once -- verified by bitmap AND by an order-independent checksum, because a bitmap alone
// would not notice a value that arrived torn between two other tags' bits.
template <class Q>
StressStats stress_conservation(Q& q, size_t producers, size_t consumers,
                                size_t per_producer) {
  const size_t total = producers * per_producer;

  std::atomic<size_t> consumed{0};
  std::atomic<bool> all_done{false};
  std::vector<uint64_t> full_hits(producers, 0);
  std::vector<uint64_t> empty_hits(consumers, 0);
  std::vector<std::vector<uint64_t>> taken(consumers);
  for (auto& t : taken) t.reserve(total / consumers + 64);

  std::vector<std::thread> threads;
  threads.reserve(producers + consumers);

  for (size_t c = 0; c < consumers; c++) {
    threads.emplace_back([&, c] {
      uint64_t v = 0;
      for (;;) {
        if (q.try_pop(v)) {
          taken[c].push_back(v);
          if (consumed.fetch_add(1, std::memory_order_relaxed) + 1 == total) {
            all_done.store(true, std::memory_order_release);
          }
        } else {
          // all_done is only set once EVERY item has been counted, so a consumer can
          // never exit while an item is still in flight -- which would show up as a lost
          // item and be indistinguishable from a real queue bug.
          if (all_done.load(std::memory_order_acquire)) break;
          empty_hits[c]++;
          std::this_thread::yield();
        }
      }
    });
  }

  for (size_t p = 0; p < producers; p++) {
    threads.emplace_back([&, p] {
      for (size_t i = 0; i < per_producer; i++) {
        const uint64_t tag = static_cast<uint64_t>(p) * per_producer + i;
        while (!q.try_push(uint64_t{tag})) {
          // A full queue is backpressure, not an error (SPEC 3.6 / S10). The production
          // pipeline spins briefly then blocks on a condvar; here we just yield, because
          // the point of this test is the queue, not the waiting policy.
          full_hits[p]++;
          std::this_thread::yield();
        }
      }
    });
  }

  for (auto& t : threads) t.join();

  // --- the actual conservation assertion --------------------------------------------
  std::vector<uint8_t> seen(total, 0);
  uint64_t got_checksum = 0;
  size_t delivered = 0;
  size_t duplicates = 0, out_of_range = 0;
  for (size_t c = 0; c < consumers; c++) {
    for (uint64_t v : taken[c]) {
      delivered++;
      if (v >= total) {
        out_of_range++;
        continue;
      }
      if (seen[v]) duplicates++;
      seen[v] = 1;
      got_checksum ^= mix(v);
    }
  }
  uint64_t want_checksum = 0;
  for (size_t v = 0; v < total; v++) want_checksum ^= mix(static_cast<uint64_t>(v));

  size_t missing = 0;
  for (size_t v = 0; v < total; v++)
    if (!seen[v]) missing++;

  CHECK_EQ(delivered, total);
  CHECK_EQ(duplicates, size_t{0});
  CHECK_EQ(out_of_range, size_t{0});
  CHECK_EQ(missing, size_t{0});
  CHECK_EQ(got_checksum, want_checksum);

  StressStats s;
  for (uint64_t f : full_hits) s.full_hits += f;
  for (uint64_t e : empty_hits) s.empty_hits += e;
  return s;
}

}  // namespace

// ===========================================================================
// SpscRing -- single-threaded invariants
// ===========================================================================

TEST(spsc_reports_capacity_and_starts_empty) {
  SpscRing<uint64_t, 8> q;
  CHECK_EQ(q.capacity(), size_t{8});
  CHECK(q.empty());
  CHECK_EQ(q.size_approx(), size_t{0});

  uint64_t out = 0xdeadbeef;
  CHECK(!q.try_pop(out));       // empty pop fails...
  CHECK_EQ(out, uint64_t{0xdeadbeef});  // ...and does not touch the caller's variable
}

TEST(spsc_fills_to_exactly_capacity_then_refuses) {
  // Cap slots means Cap items: the monotonic-counter design wastes no slot to
  // distinguish full from empty (see spsc_ring.h). Asserting the exact number is how we
  // would catch a regression to the "one wasted slot" formulation.
  SpscRing<uint64_t, 8> q;
  for (uint64_t i = 0; i < 8; i++) {
    TCTX("i=" << i);
    CHECK(q.try_push(uint64_t{i}));
  }
  CHECK_EQ(q.size_approx(), size_t{8});
  CHECK(!q.try_push(uint64_t{999}));  // full
  CHECK(!q.try_push(uint64_t{999}));  // still full, and the refusal is idempotent

  uint64_t out = 0;
  CHECK(q.try_pop(out));
  CHECK_EQ(out, uint64_t{0});
  CHECK(q.try_push(uint64_t{999}));  // one slot freed, exactly one push accepted
  CHECK(!q.try_push(uint64_t{1000}));
}

TEST(spsc_preserves_fifo_across_many_laps) {
  // 4096 laps of a 4-slot ring. The interesting arithmetic is the masking: if `head` and
  // `tail` were wrapped rather than masked-at-access, this is where they would disagree.
  constexpr size_t kCap = 4;
  constexpr uint64_t kItems = kCap * 4096;
  SpscRing<uint64_t, kCap> q;
  uint64_t next_push = 0, next_pop = 0;
  while (next_pop < kItems) {
    while (next_push < kItems && q.try_push(uint64_t{next_push})) next_push++;
    uint64_t out = 0;
    REQUIRE(q.try_pop(out));
    TCTX("expected=" << next_pop);
    CHECK_EQ(out, next_pop);
    next_pop++;
  }
  CHECK(q.empty());
  std::printf("    note: %llu items through a %zu-slot ring (%llu laps)\n",
              static_cast<unsigned long long>(kItems), kCap,
              static_cast<unsigned long long>(kItems / kCap));
}

TEST(spsc_matches_a_deque_model_under_random_interleaving) {
  constexpr size_t kCap = 16;
  SpscRing<uint64_t, kCap> q;
  model_check(q, kCap, testing::seed() ^ 0x5350534311111111ull, 200000);
}

TEST(spsc_round_trips_move_only_types) {
  const int64_t live_before = tracked_live().load();
  {
    SpscRing<std::unique_ptr<uint64_t>, 4> up;
    for (uint64_t i = 0; i < 4; i++) CHECK(up.try_push(std::make_unique<uint64_t>(i * 7)));
    CHECK(!up.try_push(std::make_unique<uint64_t>(99)));
    for (uint64_t i = 0; i < 4; i++) {
      TCTX("i=" << i);
      std::unique_ptr<uint64_t> out;
      REQUIRE(up.try_pop(out));
      REQUIRE(out != nullptr);
      CHECK_EQ(*out, i * 7);
    }
  }
  {
    // Tracked has deleted copy operations, so this instantiation failing to compile IS
    // the assertion that the ring never copies. The live count then proves that every
    // constructed value was destroyed exactly once.
    SpscRing<Tracked, 4> tq;
    for (uint64_t i = 0; i < 4; i++) CHECK(tq.try_push(Tracked(1000 + i)));
    CHECK_EQ(tracked_live().load(), live_before + 4);
    Tracked out(0);
    for (uint64_t i = 0; i < 4; i++) {
      TCTX("i=" << i);
      REQUIRE(tq.try_pop(out));
      CHECK_EQ(out.tag, 1000 + i);
    }
    // Deliberately leave items in the ring: the destructor must clean them up, and a leak
    // here would show as a nonzero delta below.
    CHECK(tq.try_push(Tracked(4242)));
    CHECK(tq.try_push(Tracked(4243)));
  }
  CHECK_EQ(tracked_live().load(), live_before);
}

TEST(spsc_head_and_tail_sit_on_separate_cache_lines) {
  // SPEC 2.5 measured the L1 line at 64 bytes. Two threads sharing one line costs more
  // than the mutex this queue replaces, and would change nothing observable except the
  // benchmark -- hence an assertion rather than a comment.
  SpscRing<uint64_t, 64> q;
  const uintptr_t h = q.head_addr(), t = q.tail_addr();
  const uintptr_t d = (h > t) ? (h - t) : (t - h);
  CHECK_GE(d, uintptr_t{kCacheLine});
  CHECK_EQ(h % kCacheLine, uintptr_t{0});
  CHECK_EQ(t % kCacheLine, uintptr_t{0});
  std::printf("    note: spsc head/tail %llu bytes apart (line = %zu)\n",
              static_cast<unsigned long long>(d), kCacheLine);
}

// ===========================================================================
// MpmcQueue -- single-threaded invariants
// ===========================================================================

TEST(mpmc_rounds_capacity_up_to_a_power_of_two) {
  // The convention this asserts: capacity() reports the ROUNDED value, i.e. what the
  // queue will actually hold, never the number that was asked for. A caller sizing a
  // memory budget needs the truth, not its own input echoed back.
  struct Case { size_t asked, want; };
  const Case cases[] = {{0, 2}, {1, 2}, {2, 2}, {3, 4}, {4, 4},
                        {5, 8}, {1000, 1024}, {1024, 1024}, {1025, 2048}};
  for (const auto& c : cases) {
    TCTX("asked=" << c.asked);
    MpmcQueue<uint64_t> q(c.asked);
    CHECK_EQ(q.capacity(), c.want);
  }
}

TEST(mpmc_fills_to_exactly_capacity_then_refuses) {
  MpmcQueue<uint64_t> q(4);
  uint64_t out = 0xfeedface;
  CHECK(!q.try_pop(out));
  CHECK_EQ(out, uint64_t{0xfeedface});

  for (uint64_t i = 0; i < 4; i++) {
    TCTX("i=" << i);
    CHECK(q.try_push(uint64_t{i}));
  }
  CHECK(!q.try_push(uint64_t{99}));
  CHECK(!q.try_push(uint64_t{99}));

  CHECK(q.try_pop(out));
  CHECK_EQ(out, uint64_t{0});
  CHECK(q.try_push(uint64_t{99}));
  CHECK(!q.try_push(uint64_t{100}));
}

TEST(mpmc_preserves_fifo_across_many_laps) {
  MpmcQueue<uint64_t> q(4);
  constexpr uint64_t kItems = 4 * 4096;
  uint64_t next_push = 0, next_pop = 0;
  while (next_pop < kItems) {
    while (next_push < kItems && q.try_push(uint64_t{next_push})) next_push++;
    uint64_t out = 0;
    REQUIRE(q.try_pop(out));
    TCTX("expected=" << next_pop);
    CHECK_EQ(out, next_pop);
    next_pop++;
  }
  std::printf("    note: %llu items through a 4-cell Vyukov queue (%llu laps)\n",
              static_cast<unsigned long long>(kItems),
              static_cast<unsigned long long>(kItems / 4));
}

TEST(mpmc_matches_a_deque_model_under_random_interleaving) {
  MpmcQueue<uint64_t> q(16);
  model_check(q, q.capacity(), testing::seed() ^ 0x4d504d4322222222ull, 200000);
}

TEST(mpmc_round_trips_move_only_types) {
  const int64_t live_before = tracked_live().load();
  {
    MpmcQueue<std::unique_ptr<uint64_t>> up(4);
    for (uint64_t i = 0; i < 4; i++) CHECK(up.try_push(std::make_unique<uint64_t>(i * 11)));
    CHECK(!up.try_push(std::make_unique<uint64_t>(99)));
    for (uint64_t i = 0; i < 4; i++) {
      TCTX("i=" << i);
      std::unique_ptr<uint64_t> out;
      REQUIRE(up.try_pop(out));
      REQUIRE(out != nullptr);
      CHECK_EQ(*out, i * 11);
    }
  }
  {
    MpmcQueue<Tracked> tq(4);
    for (uint64_t i = 0; i < 4; i++) CHECK(tq.try_push(Tracked(2000 + i)));
    CHECK_EQ(tracked_live().load(), live_before + 4);
    Tracked out(0);
    for (uint64_t i = 0; i < 4; i++) {
      TCTX("i=" << i);
      REQUIRE(tq.try_pop(out));
      CHECK_EQ(out.tag, 2000 + i);
    }
    CHECK(tq.try_push(Tracked(7777)));  // left behind for the destructor to clean up
  }
  CHECK_EQ(tracked_live().load(), live_before);
}

TEST(mpmc_positions_sit_on_separate_cache_lines) {
  MpmcQueue<uint64_t> q(64);
  const uintptr_t e = q.enqueue_pos_addr(), d = q.dequeue_pos_addr();
  const uintptr_t dist = (e > d) ? (e - d) : (d - e);
  CHECK_GE(dist, uintptr_t{kCacheLine});
  std::printf("    note: mpmc enqueue/dequeue positions %llu bytes apart\n",
              static_cast<unsigned long long>(dist));
}

// ===========================================================================
// The atomics themselves (SPEC 2.5)
// ===========================================================================

TEST(queue_positions_use_genuinely_lock_free_atomics) {
  // If std::atomic<size_t> fell back to a mutex, both of these queues would still compile
  // and still be correct -- and "lock-free queues on the hot path" would be a lie with no
  // failing test anywhere. SPEC 2.5 measured this; T4 re-asserts it where it is used.
  static_assert(std::atomic<size_t>::is_always_lock_free,
                "SPEC 2.5: the Vyukov slot counter must not be a mutex in disguise");
  std::atomic<size_t> a{0};
  CHECK(a.is_lock_free());
}

// ===========================================================================
// Item conservation under concurrency (SPEC S9) -- the tests that matter
// ===========================================================================

TEST(spsc_conserves_every_item_through_a_tiny_ring) {
  // Capacity 4 against 60 000 items: the ring wraps 15 000 times and both full and empty
  // are hit continuously, which is exactly the region where an off-by-one in the
  // acquire/release pairing shows up.
  constexpr size_t kCap = 4;
  constexpr size_t kItems = 60000;
  SpscRing<uint64_t, kCap> q;
  const StressStats s = stress_conservation(q, 1, 1, kItems);
  CHECK_GT(s.full_hits, uint64_t{0});
  CHECK_GT(s.empty_hits, uint64_t{0});
  std::printf("    note: spsc 1p/1c cap=%zu items=%zu  full-hits=%llu empty-hits=%llu\n",
              kCap, kItems, static_cast<unsigned long long>(s.full_hits),
              static_cast<unsigned long long>(s.empty_hits));
}

TEST(spsc_conserves_every_item_through_a_roomy_ring) {
  // The control for the test above: a ring big enough that backpressure is rare, so a bug
  // that only appears when the ring is NOT saturated has somewhere to show up.
  constexpr size_t kCap = 1024;
  constexpr size_t kItems = 60000;
  SpscRing<uint64_t, kCap> q;
  const StressStats s = stress_conservation(q, 1, 1, kItems);
  std::printf("    note: spsc 1p/1c cap=%zu items=%zu  full-hits=%llu empty-hits=%llu\n",
              kCap, kItems, static_cast<unsigned long long>(s.full_hits),
              static_cast<unsigned long long>(s.empty_hits));
}

TEST(mpmc_conserves_every_item_at_1_2_4_8_producers) {
  struct Case { size_t producers, consumers, cap, per_producer; };
  const Case cases[] = {
      {1, 1, 4, 20000},  {2, 1, 4, 10000},  {4, 1, 4, 5000},   {8, 1, 4, 2500},
      {1, 2, 4, 20000},  {2, 2, 4, 10000},  {4, 2, 4, 5000},   {8, 2, 4, 2500},
      // Roomy control: contention on the positions instead of on the backpressure path.
      {8, 2, 1024, 2500},
  };
  for (const auto& c : cases) {
    TCTX("producers=" << c.producers << " consumers=" << c.consumers << " cap=" << c.cap);
    MpmcQueue<uint64_t> q(c.cap);
    const StressStats s = stress_conservation(q, c.producers, c.consumers, c.per_producer);
    std::printf("    note: mpmc %zup/%zuc cap=%zu items=%zu  full-hits=%llu "
                "empty-hits=%llu\n",
                c.producers, c.consumers, q.capacity(), c.producers * c.per_producer,
                static_cast<unsigned long long>(s.full_hits),
                static_cast<unsigned long long>(s.empty_hits));
  }
}

TEST(mpmc_conserves_move_only_payloads_under_contention) {
  // The uint64 stress above cannot catch a bug in the placement-new / explicit-destructor
  // path, because a uint64 has neither. This one does: every Tracked constructed must be
  // destroyed exactly once, across 4 producers and 2 consumers on a 4-cell queue.
  const int64_t live_before = tracked_live().load();
  constexpr size_t kProducers = 4, kConsumers = 2, kPerProducer = 5000;
  const size_t total = kProducers * kPerProducer;

  MpmcQueue<Tracked> q(4);
  std::atomic<size_t> consumed{0};
  std::atomic<bool> all_done{false};
  std::vector<std::vector<uint64_t>> taken(kConsumers);
  std::vector<std::thread> threads;

  for (size_t c = 0; c < kConsumers; c++) {
    threads.emplace_back([&, c] {
      Tracked out(0);
      for (;;) {
        if (q.try_pop(out)) {
          taken[c].push_back(out.tag);
          if (consumed.fetch_add(1, std::memory_order_relaxed) + 1 == total) {
            all_done.store(true, std::memory_order_release);
          }
        } else {
          if (all_done.load(std::memory_order_acquire)) break;
          std::this_thread::yield();
        }
      }
    });
  }
  for (size_t p = 0; p < kProducers; p++) {
    threads.emplace_back([&, p] {
      for (size_t i = 0; i < kPerProducer; i++) {
        Tracked item(static_cast<uint64_t>(p) * kPerProducer + i);
        // try_push_moving, NOT try_push: the by-value form would destroy `item` along
        // with its parameter on every refused attempt, and this loop refuses constantly.
        // That distinction is exactly why the second entry point exists.
        while (!q.try_push_moving(item)) std::this_thread::yield();
      }
    });
  }
  for (auto& t : threads) t.join();

  std::vector<uint8_t> seen(total, 0);
  size_t delivered = 0, duplicates = 0, missing = 0;
  for (size_t c = 0; c < kConsumers; c++) {
    for (uint64_t v : taken[c]) {
      delivered++;
      REQUIRE(v < total);
      if (seen[v]) duplicates++;
      seen[v] = 1;
    }
  }
  for (size_t v = 0; v < total; v++)
    if (!seen[v]) missing++;

  CHECK_EQ(delivered, total);
  CHECK_EQ(duplicates, size_t{0});
  CHECK_EQ(missing, size_t{0});
  CHECK_EQ(tracked_live().load(), live_before);
  std::printf("    note: mpmc move-only %zup/%zuc cap=%zu items=%zu, net live objects %lld\n",
              kProducers, kConsumers, q.capacity(), total,
              static_cast<long long>(tracked_live().load() - live_before));
}

// ===========================================================================
// T4 ADVERSARIAL PASS -- tests written to BREAK the two headers above.
//
// Everything before this line was written alongside the implementation, which is exactly
// the failure mode SPEC 6 warns about: a test suite that agrees with the code because the
// same person wrote both. These were written afterwards, against the SPEC text, by
// looking for the input the implementation would not survive.
// ===========================================================================

// ---------------------------------------------------------------------------
// Hostile CAPACITY (SPEC S7's principle applied to a caller-supplied size)
// ---------------------------------------------------------------------------
//
// S7 is stated about frames -- "a declared length is range-checked against a hard cap
// BEFORE any allocation" -- but the rule is about arithmetic, not about frames, and
// MpmcQueue's capacity is a number that reaches it from configuration. Two failures were
// found here, both from the same missing check:
//
//   capacity > 2^63  -> round_up_pow2's `p <<= 1` shifted the high bit out, p became 0,
//                       and `while (p < n)` never terminated. The process HUNG. There is
//                       no output, no error and no crash to diagnose -- the worst shape a
//                       failure can have.
//   capacity ~ 2^62  -> the loop terminated and `new Cell[cap_]` threw std::bad_alloc,
//                       which in this codebase is std::terminate: result.h says plainly
//                       that wanrep does not use exceptions, so nothing anywhere catches
//                       one. A configuration typo became an abort with no message.
//
// Both are now impossible: the request is clamped to MpmcQueue<T>::kMaxCapacity before it
// is used to size anything, and capacity() keeps reporting the truth about what the queue
// actually holds.
TEST(mpmc_clamps_an_absurd_capacity_instead_of_hanging_or_aborting) {
  using Q = MpmcQueue<uint64_t>;
  static_assert(Q::kMaxCapacity >= 2, "the clamp must still leave a usable queue");
  static_assert((Q::kMaxCapacity & (Q::kMaxCapacity - 1)) == 0,
                "the clamp must itself be a power of two, or `pos & mask` breaks");

  // The whole hostile range, including the exact bit patterns that used to hang: one past
  // the largest representable power of two, and all-ones.
  const size_t hostile[] = {
      Q::kMaxCapacity + 1,
      size_t{1} << 62,
      size_t{1} << 63,
      (size_t{1} << 63) + 1,
      SIZE_MAX - 1,
      SIZE_MAX,
  };
  for (size_t asked : hostile) {
    TCTX("asked=" << asked);
    Q q(asked);
    // Clamped, not echoed back and not rounded into an allocation nobody can serve.
    CHECK_EQ(q.capacity(), Q::kMaxCapacity);
    // And it is a working queue afterwards, not a wedged one.
    CHECK(q.try_push(uint64_t{7}));
    uint64_t out = 0;
    REQUIRE(q.try_pop(out));
    CHECK_EQ(out, uint64_t{7});
  }
  std::printf("    note: absurd capacities clamped to %zu cells (largest asked: SIZE_MAX)\n",
              Q::kMaxCapacity);
}

TEST(mpmc_capacity_rounding_is_still_exact_below_the_clamp) {
  // The clamp must not disturb the ordinary contract that the test above this file's
  // adversarial section already pinned. Re-asserted at the clamp boundary itself, which
  // is the one place a `<` / `<=` slip would hide.
  using Q = MpmcQueue<uint64_t>;
  CHECK_EQ(MpmcQueue<uint64_t>(Q::kMaxCapacity).capacity(), Q::kMaxCapacity);
  CHECK_EQ(MpmcQueue<uint64_t>(Q::kMaxCapacity - 1).capacity(), Q::kMaxCapacity);
  CHECK_EQ(MpmcQueue<uint64_t>(Q::kMaxCapacity / 2).capacity(), Q::kMaxCapacity / 2);
  CHECK_EQ(MpmcQueue<uint64_t>(Q::kMaxCapacity / 2 + 1).capacity(), Q::kMaxCapacity);
}

// ---------------------------------------------------------------------------
// size_approx() must be approximate, not nonsense
// ---------------------------------------------------------------------------
//
// The original loaded head_ first and tail_ second and returned `head - tail`. tail only
// moves forward, so between the two loads the consumer can push tail PAST the head
// snapshot -- and the subtraction is size_t, so the result is not "slightly stale", it is
// 18446744073709551615. Measured on a capacity-2 ring: 465 such readings in 105 million
// observations, i.e. it is rare enough to never show up in a test that only runs once and
// common enough to appear in production logs within seconds.
//
// "Approximate" was always the documented contract and that is fine. A depth gauge that
// occasionally reports 1.8e19 is not approximate; it is wrong, and a caller multiplying it
// by an item size to estimate memory (SPEC S10 is about exactly that kind of accounting)
// gets an answer with no relationship to reality. The contract is now the useful one:
// the answer is always in [0, capacity()].
TEST(spsc_size_approx_stays_within_capacity_under_concurrency) {
  // Capacity 2 on purpose: the smaller the ring, the more often tail overtakes the head
  // snapshot, so this is the shape that exposes the underflow soonest.
  constexpr size_t kCap = 2;
  constexpr uint64_t kObservations = 8u * 1000 * 1000;

  SpscRing<uint64_t, kCap> q;
  std::atomic<bool> stop{false};
  std::atomic<uint64_t> out_of_range{0};
  uint64_t worst = 0;

  std::thread producer([&] {
    uint64_t i = 0;
    while (!stop.load(std::memory_order_relaxed)) q.try_push(uint64_t{i++});
  });
  std::thread consumer([&] {
    uint64_t v = 0;
    while (!stop.load(std::memory_order_relaxed)) q.try_pop(v);
  });

  // A fixed OBSERVATION COUNT, not a duration: SPEC S15 forbids wall-clock in test logic,
  // and a count is also the thing that stays honest when a sanitizer slows everything by
  // an order of magnitude.
  for (uint64_t n = 0; n < kObservations; n++) {
    const size_t s = q.size_approx();
    if (s > kCap) {
      out_of_range.fetch_add(1, std::memory_order_relaxed);
      if (s > worst) worst = s;
    }
  }
  stop.store(true, std::memory_order_relaxed);
  producer.join();
  consumer.join();

  TCTX("worst reading=" << worst << " capacity=" << kCap);
  CHECK_EQ(out_of_range.load(), uint64_t{0});
  std::printf("    note: %llu concurrent size_approx() readings, %llu outside [0, %zu]"
              " (worst %llu)\n",
              static_cast<unsigned long long>(kObservations),
              static_cast<unsigned long long>(out_of_range.load()), kCap,
              static_cast<unsigned long long>(worst));
}

// ---------------------------------------------------------------------------
// Destructor reclamation at every wrap offset
// ---------------------------------------------------------------------------
//
// Both destructors walk [tail, head) / [dequeue_pos, enqueue_pos) and call ~T() on each.
// The existing move-only tests leave items behind, but only ever with the positions near
// zero, where an off-by-one in the masking and an off-by-one in the range look identical.
// These sweep the phase: the live window is placed at every offset within a lap and at
// every length from empty to full, and Tracked's live count is the oracle -- it catches a
// slot destroyed twice (count goes negative) and a slot never destroyed (count stays up),
// which a bitmap cannot see.
TEST(spsc_destructor_reclaims_leftovers_at_every_wrap_offset) {
  constexpr size_t kCap = 4;
  for (size_t skew = 0; skew < 2 * kCap + 1; skew++) {
    for (size_t left = 0; left <= kCap; left++) {
      TCTX("skew=" << skew << " left=" << left);
      const int64_t before = tracked_live().load();
      {
        SpscRing<Tracked, kCap> q;
        // Push-and-pop `skew` times so the live window does not begin at slot 0.
        for (size_t i = 0; i < skew; i++) {
          Tracked in(i);
          REQUIRE(q.try_push_moving(in));
          Tracked out(0);
          REQUIRE(q.try_pop(out));
        }
        for (size_t i = 0; i < left; i++) {
          Tracked in(1000 + i);
          REQUIRE(q.try_push_moving(in));
        }
        CHECK_EQ(tracked_live().load(), before + static_cast<int64_t>(left));
      }  // <- the destructor is the thing under test
      CHECK_EQ(tracked_live().load(), before);
    }
  }
}

TEST(mpmc_destructor_reclaims_leftovers_at_every_wrap_offset) {
  constexpr size_t kCap = 4;
  for (size_t skew = 0; skew < 2 * kCap + 1; skew++) {
    for (size_t left = 0; left <= kCap; left++) {
      TCTX("skew=" << skew << " left=" << left);
      const int64_t before = tracked_live().load();
      {
        MpmcQueue<Tracked> q(kCap);
        for (size_t i = 0; i < skew; i++) {
          Tracked in(i);
          REQUIRE(q.try_push_moving(in));
          Tracked out(0);
          REQUIRE(q.try_pop(out));
        }
        for (size_t i = 0; i < left; i++) {
          Tracked in(1000 + i);
          REQUIRE(q.try_push_moving(in));
        }
        CHECK_EQ(tracked_live().load(), before + static_cast<int64_t>(left));
      }
      CHECK_EQ(tracked_live().load(), before);
    }
  }
}

// ---------------------------------------------------------------------------
// A refused push must not consume the caller's item (the retry-loop trap)
// ---------------------------------------------------------------------------
//
// This is the highest-severity finding of the adversarial pass, and it was found by
// reading the FIRST CALLER rather than the queue. try_push used to take its argument BY
// VALUE, so `while (!q.try_push(std::move(item))) yield;` moved `item` into the parameter
// on attempt one and destroyed it there when the push was refused; every retry after that
// pushed a moved-from husk. The queue's own header documented the hazard in capital
// letters and provided try_push_moving to avoid it -- and include/wanrep/protocol.h's
// push_blocking() then wrote exactly the forbidden loop anyway.
//
// The damage is not a crash and not a lost item -- it is WORSE than either, because the
// item still ARRIVES. Reproduced against the real queue with protocol.h's own RawBatch:
//
//     pushing:  seq=42 chunks=3 payload=4096 bytes
//     drained:  seq=42 chunks=3 payload=0 bytes
//
// The scalars survive (a moved-from int keeps its value); the std::vector payload does
// not. So a batch announcing three chunks arrives carrying zero bytes, only when the
// queue was full, i.e. only under load. That is SPEC S1 -- replicated data is wrong --
// reached without a single failed check anywhere in the transport.
//
// The fix is in the queue, not in a comment: try_push now takes T&&, so a refused push
// never touches the caller's object and the natural retry loop is the correct one.
// try_push_moving stays for lvalue call sites. A trap that the queue's own author warned
// about and the very next caller fell into is not a documentation problem.
TEST(a_refused_push_does_not_consume_the_callers_item) {
  // Deterministic, single-threaded: fill to capacity, then refuse repeatedly. Concurrency
  // is not needed to show this and would only make it look like a race, which it is not.
  constexpr size_t kPayload = 4096;
  {
    SpscRing<std::vector<uint8_t>, 2> q;
    REQUIRE(q.try_push(std::vector<uint8_t>(8, 1)));
    REQUIRE(q.try_push(std::vector<uint8_t>(8, 2)));

    std::vector<uint8_t> item(kPayload, 0xAB);
    for (int attempt = 0; attempt < 5; attempt++) {
      TCTX("spsc refused attempt=" << attempt);
      CHECK(!q.try_push(std::move(item)));      // refused: this is backpressure, not an error
      CHECK_EQ(item.size(), kPayload);          // ...and the caller still owns its buffer
    }
    std::vector<uint8_t> drained;
    REQUIRE(q.try_pop(drained));                // one slot freed
    REQUIRE(q.try_push(std::move(item)));       // the SAME item, never rebuilt
    std::vector<uint8_t> got;
    REQUIRE(q.try_pop(got));                    // (the other filler)
    REQUIRE(q.try_pop(got));
    CHECK_EQ(got.size(), kPayload);             // arrived whole, not as a moved-from husk
    CHECK_EQ(got[0], uint8_t{0xAB});
    CHECK_EQ(got[kPayload - 1], uint8_t{0xAB});
  }
  {
    MpmcQueue<std::vector<uint8_t>> q(2);
    REQUIRE(q.try_push(std::vector<uint8_t>(8, 1)));
    REQUIRE(q.try_push(std::vector<uint8_t>(8, 2)));

    std::vector<uint8_t> item(kPayload, 0xCD);
    for (int attempt = 0; attempt < 5; attempt++) {
      TCTX("mpmc refused attempt=" << attempt);
      CHECK(!q.try_push(std::move(item)));
      CHECK_EQ(item.size(), kPayload);
    }
    std::vector<uint8_t> got;
    REQUIRE(q.try_pop(got));
    REQUIRE(q.try_push(std::move(item)));
    REQUIRE(q.try_pop(got));
    REQUIRE(q.try_pop(got));
    CHECK_EQ(got.size(), kPayload);
    CHECK_EQ(got[kPayload - 1], uint8_t{0xCD});
  }
}

TEST(the_natural_retry_loop_delivers_the_whole_payload) {
  // protocol.h's push_blocking(), reproduced as a caller would write it, against a queue
  // small enough that the loop is guaranteed to spin. If the payload survives this, the
  // idiom is safe for every caller -- which is the property that has to hold, because the
  // idiom is what people write.
  struct Batch {
    uint64_t seq = 0;
    std::vector<uint8_t> payload;
    size_t chunks = 0;
  };
  constexpr size_t kBatches = 200, kPayload = 1024;

  MpmcQueue<Batch> q(2);
  std::atomic<size_t> received{0};
  std::atomic<size_t> short_payloads{0};

  std::thread consumer([&] {
    Batch out;
    while (received.load(std::memory_order_acquire) < kBatches) {
      if (q.try_pop(out)) {
        if (out.payload.size() != kPayload || out.chunks != 3) {
          short_payloads.fetch_add(1, std::memory_order_relaxed);
        }
        received.fetch_add(1, std::memory_order_release);
      } else {
        std::this_thread::yield();
      }
    }
  });

  for (size_t i = 0; i < kBatches; i++) {
    Batch b;
    b.seq = i;
    b.chunks = 3;
    b.payload.assign(kPayload, static_cast<uint8_t>(0xA5));
    while (!q.try_push(std::move(b))) std::this_thread::yield();  // the idiom, verbatim
  }
  consumer.join();

  TCTX("batches=" << kBatches);
  CHECK_EQ(short_payloads.load(), size_t{0});
  std::printf("    note: %zu batches through a 2-cell queue under continuous backpressure,"
              " %zu truncated\n", kBatches, short_payloads.load());
}

// A refused push must also not LEAK the temporary it was handed. Under sustained
// backpressure -- the pipeline's normal state, not an edge case -- one leaked object per
// refusal is unbounded growth, i.e. a direct S10 violation.
TEST(refused_push_of_a_temporary_leaks_nothing) {
  for (int which = 0; which < 2; which++) {
    TCTX("queue=" << (which == 0 ? "spsc" : "mpmc"));
    const int64_t before = tracked_live().load();
    {
      SpscRing<Tracked, 2> sq;
      MpmcQueue<Tracked> mq(2);
      Tracked a(1), b(2);
      if (which == 0) {
        REQUIRE(sq.try_push_moving(a));
        REQUIRE(sq.try_push_moving(b));
        for (int i = 0; i < 1000; i++) CHECK(!sq.try_push(Tracked(9000 + i)));
        CHECK_EQ(tracked_live().load(), before + 2);  // the two queued, nothing else
      } else {
        REQUIRE(mq.try_push_moving(a));
        REQUIRE(mq.try_push_moving(b));
        for (int i = 0; i < 1000; i++) CHECK(!mq.try_push(Tracked(9000 + i)));
        CHECK_EQ(tracked_live().load(), before + 2);
      }
    }
    CHECK_EQ(tracked_live().load(), before);
  }
}

// ---------------------------------------------------------------------------
// Conservation with more threads than cores, on the smallest legal queue
// ---------------------------------------------------------------------------
//
// The existing stress runs up to 8 producers on an 8-core box, so a thread is usually
// left alone between claiming a Vyukov ticket and publishing it. That window -- ticket
// claimed, cell not yet published -- is where the sequence-number handshake either works
// or loses an item, and it is only wide when threads are PREEMPTED inside it. So this one
// deliberately oversubscribes (24 threads) on a 2-cell queue, which makes every operation
// contend and makes preemption mid-ticket the common case rather than the rare one.
TEST(mpmc_conserves_every_item_when_threads_outnumber_cores) {
  struct Case { size_t producers, consumers, cap, per_producer; };
  const Case cases[] = {
      {16, 8, 2, 2000},   // maximum contention: smallest legal queue, 3x oversubscribed
      {32, 1, 2, 1000},   // fan-in extreme: every producer fights for the same ticket
      {1, 32, 2, 20000},  // fan-out extreme: 32 consumers starving on a 2-cell queue
      {7, 5, 3, 8000},    // capacity 3 -> rounds to 4; a non-power-of-two request in anger
  };
  for (const auto& c : cases) {
    TCTX("producers=" << c.producers << " consumers=" << c.consumers << " cap=" << c.cap);
    MpmcQueue<uint64_t> q(c.cap);
    const StressStats s = stress_conservation(q, c.producers, c.consumers, c.per_producer);
    std::printf("    note: mpmc %zup/%zuc cap=%zu items=%zu  full-hits=%llu empty-hits=%llu\n",
                c.producers, c.consumers, q.capacity(), c.producers * c.per_producer,
                static_cast<unsigned long long>(s.full_hits),
                static_cast<unsigned long long>(s.empty_hits));
  }
}

RUN_ALL()
