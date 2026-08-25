// bench/queues (SPEC 4.3, R2.2, 8.5): the lock-free queues against a std::mutex +
// std::condition_variable baseline, at 1/2/4/8 producers and 1 or 2 consumers.
//
// THIS BENCHMARK DECIDES A HEADLINE CLAIM, so it is written to be able to say "no".
// SPEC 8.5 states the expectation in advance, which is the only way a benchmark can
// falsify anything: an uncontended std::mutex on Linux is a couple of atomic operations
// and never enters the kernel, and T1 measured a pipeline item as ~8.5 us of upstream
// chunk+SHA-256 work (966 MB/s at an 8 KiB chunk). If a queue operation costs tens of
// nanoseconds either way, the queue is not the bottleneck and the lock-free version may
// measure the same as the mutex. If that is the answer, it is printed plainly and the
// claim is reworded from a performance claim to a design claim. The benchmark is NOT
// tuned until lock-free wins.
//
// WHAT IS MEASURED, AND THE THREE TABLES:
//   Table 1 runs all three queues through ONE harness with ONE waiting policy: the
//     non-blocking try_* API plus spin-and-yield on full/empty. Everything except the
//     data structure is held constant, so the difference is the data structure.
//   Table 2 runs the mutex queue in its NATURAL blocking form (condvar wait on full and
//     on empty). That is what an engineer would actually write, and its condvar
//     block/wake traffic is precisely the cost the lock-free design exists to avoid --
//     so leaving it out would flatter the baseline, and leaving out Table 1 would flatter
//     the lock-free queues by charging the baseline for a policy rather than a structure.
//   Table 3 exists because Tables 1 and 2 are not the workload. In them a producer does
//     nothing but push, so the queue is 100% of the work and contention is at its
//     theoretical maximum -- the regime most favourable to a lock-free design. Table 3
//     restores T1's measured ~8.5 us of upstream work per item, which is what SPEC 8.5's
//     prediction was actually about, and it is the table that can make our own queues
//     look unnecessary. It is run and reported either way.
//   None of the three is "the" number on its own.
//
// LATENCY CAVEAT, stated because it is large here: SPEC 2.5 measured steady_clock
// granularity at ~41 ns and this run re-measures it. A push can cost less than one tick,
// so a p50 sitting at the tick means "under one tick", not "exactly one tick" -- the
// clock cannot resolve further and the benchmark does not pretend otherwise.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <new>
#include <thread>
#include <utility>
#include <vector>

#include "wanrep/mpmc_queue.h"
#include "wanrep/spsc_ring.h"

using namespace wanrep;

namespace {

using Clock = std::chrono::steady_clock;

// A stand-in for a pipeline item: a handle plus its plan sequence number (SPEC 3.3). The
// real item owns a buffer, but the buffer is moved, not copied, so what actually travels
// through the queue is this much. Deliberately small: making the element big would
// measure memcpy, not the queue.
struct Item {
  uint64_t seq;
  uint64_t tag;
};

// ---------------------------------------------------------------------------
// The baseline: bounded queue, std::mutex + std::condition_variable
// ---------------------------------------------------------------------------
//
// Written here rather than pulled from anywhere so the comparison is against code the
// reader can see. Two condition variables, not one: with a single condvar and
// notify_all, every producer wakes on every pop and most go straight back to sleep --
// that is a strawman, and beating a strawman proves nothing.
template <class T>
class MutexQueue {
 public:
  // 2x, because compaction lets `buf_` hold up to cap_ live items plus up to cap_ already
  // consumed ones before it is compacted. Reserving the true high-water mark keeps a
  // reallocation from showing up in the latency tail and being read as lock contention.
  explicit MutexQueue(size_t capacity) : cap_(capacity) { buf_.reserve(2 * capacity); }

  // Non-blocking form, so Table 1 can hold the waiting policy constant across all three
  // queues. Same signature as the lock-free queues' backpressure-safe push.
  bool try_push_moving(T& v) {
    std::lock_guard<std::mutex> lock(m_);
    if (buf_.size() - head_ >= cap_) return false;
    buf_.push_back(std::move(v));
    return true;
  }
  bool try_pop(T& out) {
    std::lock_guard<std::mutex> lock(m_);
    if (head_ == buf_.size()) return false;
    out = std::move(buf_[head_++]);
    compact_locked();
    return true;
  }

  // Blocking form: what this design is actually for, and Table 2's subject.
  void push(T v) {
    std::unique_lock<std::mutex> lock(m_);
    not_full_.wait(lock, [&] { return buf_.size() - head_ < cap_; });
    buf_.push_back(std::move(v));
    lock.unlock();
    not_empty_.notify_one();
  }
  // Returns false only once the queue is closed AND drained, which is how the consumer
  // threads terminate without a sentinel value.
  bool pop(T& out) {
    std::unique_lock<std::mutex> lock(m_);
    not_empty_.wait(lock, [&] { return head_ != buf_.size() || closed_; });
    if (head_ == buf_.size()) return false;  // closed and drained
    out = std::move(buf_[head_++]);
    compact_locked();
    lock.unlock();
    not_full_.notify_one();
    return true;
  }
  void close() {
    {
      std::lock_guard<std::mutex> lock(m_);
      closed_ = true;
    }
    not_empty_.notify_all();
  }

  size_t capacity() const { return cap_; }

 private:
  // A std::vector used as a ring by compaction rather than by masking. Kept simple on
  // purpose: this is the baseline, and a baseline with a clever data structure inside it
  // stops being a baseline. Compaction is amortised O(1) and happens under a lock the
  // caller already holds.
  void compact_locked() {
    if (head_ >= cap_) {
      buf_.erase(buf_.begin(), buf_.begin() + static_cast<long>(head_));
      head_ = 0;
    }
  }

  const size_t cap_;
  std::mutex m_;
  std::condition_variable not_full_;
  std::condition_variable not_empty_;
  std::vector<T> buf_;
  size_t head_ = 0;
  bool closed_ = false;
};

// ---------------------------------------------------------------------------
// Simulated upstream work (SPEC 8.5's actual claim)
// ---------------------------------------------------------------------------
//
// Table 1 and 2 are queue microbenchmarks: producers do nothing but push, so contention
// is at its theoretical maximum and the queue is 100% of the workload. That is the
// regime where a lock-free design looks best, and it is NOT the regime this pipeline
// runs in. T1 measured chunk+SHA-256 at 966 MB/s, so producing one 8 KiB pipeline item
// costs ~8.5 us of CPU before the push happens -- thousands of times a queue operation.
// Table 3 puts that work back in, which is the comparison SPEC 8.5 actually predicted
// on, and it is deliberately the one that can make our own queues look unnecessary.
//
// The work is a splitmix64 chain: data-dependent, so it cannot be vectorised or hoisted,
// and its result is accumulated into an atomic sink so the optimiser cannot delete it.
std::atomic<uint64_t> g_sink{0};

uint64_t burn(uint64_t iters, uint64_t x) {
  for (uint64_t i = 0; i < iters; i++) {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    x ^= x >> 31;
  }
  return x;
}

// Calibrated at runtime rather than hard-coded, so the number stays ~8.5 us on a machine
// with a different clock rate instead of quietly becoming a different experiment.
//
// MIN of several repetitions, never a single sample. A single sample can be inflated by
// an arbitrary amount if the calibrating thread is preempted mid-burn, and the scaling
// step then DIVIDES by that inflated time -- so one unlucky context switch silently
// produces a work loop hundreds of times too short and Table 3 quietly stops being the
// experiment it claims to be. (This is not hypothetical: it happened on the first run of
// this benchmark, and the only symptom was a Table 3 throughput ten times too high.)
// The minimum of N runs is the one statistic that is robust to being interrupted, since
// interruption can only ever make a measurement longer.
struct BurnCal {
  uint64_t iters;
  double achieved_us;  // re-measured at the chosen count, printed so it can be checked
};

double time_burn_min(uint64_t iters) {
  double best = 1e18;
  for (int r = 0; r < 5; r++) {
    const auto t0 = Clock::now();
    g_sink.fetch_add(burn(iters, 12345 + static_cast<uint64_t>(r)),
                     std::memory_order_relaxed);
    const double us = std::chrono::duration<double, std::micro>(Clock::now() - t0).count();
    best = std::min(best, us);
  }
  return best;
}

BurnCal calibrate_burn(double target_us) {
  uint64_t iters = 64;
  // Grow until the burn is long enough to be measurable well above the ~42 ns clock tick.
  while (time_burn_min(iters) < target_us && iters < (1u << 26)) iters *= 2;
  const double us = time_burn_min(iters);
  uint64_t scaled = static_cast<uint64_t>(static_cast<double>(iters) * (target_us / us));
  if (scaled < 1) scaled = 1;
  return BurnCal{scaled, time_burn_min(scaled)};
}

// ---------------------------------------------------------------------------
// Result reporting
// ---------------------------------------------------------------------------
struct Result {
  double items_per_sec = 0;
  uint64_t p50_ns = 0, p99_ns = 0, p999_ns = 0, max_ns = 0;
  uint64_t waits = 0;  // failed try_push attempts (Table 1) or 0 (Table 2)
};

Result summarize(std::vector<std::vector<uint32_t>>& per_thread, double seconds,
                 size_t total_items, uint64_t waits) {
  std::vector<uint32_t> all;
  size_t n = 0;
  for (auto& v : per_thread) n += v.size();
  all.reserve(n);
  for (auto& v : per_thread) all.insert(all.end(), v.begin(), v.end());
  std::sort(all.begin(), all.end());

  Result r;
  r.items_per_sec = static_cast<double>(total_items) / seconds;
  if (!all.empty()) {
    r.p50_ns = all[all.size() / 2];
    r.p99_ns = all[all.size() * 99 / 100];
    r.p999_ns = all[all.size() * 999 / 1000];
    r.max_ns = all.back();
  }
  r.waits = waits;
  return r;
}

void print_row(const char* queue, size_t producers, size_t consumers, const Result& r) {
  std::printf("  %-12s %2zup/%zuc  %10.2f M items/s   p50 %6llu ns  p99 %7llu ns  "
              "p99.9 %8llu ns  max %9llu ns  retries %llu\n",
              queue, producers, consumers, r.items_per_sec / 1e6,
              static_cast<unsigned long long>(r.p50_ns),
              static_cast<unsigned long long>(r.p99_ns),
              static_cast<unsigned long long>(r.p999_ns),
              static_cast<unsigned long long>(r.max_ns),
              static_cast<unsigned long long>(r.waits));
}

// ---------------------------------------------------------------------------
// Harness 1: identical non-blocking API and waiting policy for all three queues
// ---------------------------------------------------------------------------
template <class Q>
Result run_try_api(Q& q, size_t producers, size_t consumers, size_t per_producer,
                   uint64_t work_iters = 0) {
  const size_t total = producers * per_producer;
  std::atomic<bool> go{false};
  std::atomic<size_t> consumed{0};
  std::atomic<bool> all_done{false};
  std::vector<std::vector<uint32_t>> lat(producers);
  std::vector<uint64_t> retries(producers, 0);
  for (auto& v : lat) v.reserve(per_producer);

  std::vector<std::thread> threads;
  threads.reserve(producers + consumers);

  for (size_t c = 0; c < consumers; c++) {
    threads.emplace_back([&] {
      while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
      Item out{0, 0};
      for (;;) {
        if (q.try_pop(out)) {
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
  for (size_t p = 0; p < producers; p++) {
    threads.emplace_back([&, p] {
      while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
      uint64_t acc = 0x1234567 + p;
      for (size_t i = 0; i < per_producer; i++) {
        Item item{static_cast<uint64_t>(p) * per_producer + i, 0xA5A5A5A5u};
        // The upstream chunk+hash work, OUTSIDE the timed region: it is what the producer
        // does between pushes, not part of the push.
        if (work_iters) acc = burn(work_iters, acc);
        const auto t0 = Clock::now();
        // try_push_moving, not try_push: a refused by-value push would destroy the item.
        while (!q.try_push_moving(item)) {
          retries[p]++;
          std::this_thread::yield();
        }
        const auto t1 = Clock::now();
        lat[p].push_back(static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));
      }
      g_sink.fetch_add(acc, std::memory_order_relaxed);
    });
  }

  const auto start = Clock::now();
  go.store(true, std::memory_order_release);
  for (auto& t : threads) t.join();
  const double secs = std::chrono::duration<double>(Clock::now() - start).count();

  uint64_t total_retries = 0;
  for (uint64_t x : retries) total_retries += x;
  return summarize(lat, secs, total, total_retries);
}

// ---------------------------------------------------------------------------
// Harness 2: the mutex queue in its natural blocking form
// ---------------------------------------------------------------------------
Result run_blocking(MutexQueue<Item>& q, size_t producers, size_t consumers,
                    size_t per_producer) {
  const size_t total = producers * per_producer;
  std::atomic<bool> go{false};
  std::vector<std::vector<uint32_t>> lat(producers);
  for (auto& v : lat) v.reserve(per_producer);

  std::vector<std::thread> consumer_threads, producer_threads;
  for (size_t c = 0; c < consumers; c++) {
    consumer_threads.emplace_back([&] {
      Item out{0, 0};
      while (q.pop(out)) {
      }
    });
  }
  for (size_t p = 0; p < producers; p++) {
    producer_threads.emplace_back([&, p] {
      while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
      for (size_t i = 0; i < per_producer; i++) {
        Item item{static_cast<uint64_t>(p) * per_producer + i, 0xA5A5A5A5u};
        const auto t0 = Clock::now();
        q.push(std::move(item));
        const auto t1 = Clock::now();
        lat[p].push_back(static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));
      }
    });
  }

  const auto start = Clock::now();
  go.store(true, std::memory_order_release);
  for (auto& t : producer_threads) t.join();
  q.close();
  for (auto& t : consumer_threads) t.join();
  const double secs = std::chrono::duration<double>(Clock::now() - start).count();
  return summarize(lat, secs, total, 0);
}

// The instrumentation floor. Reported first because on this platform it is NOT
// negligible: the observed clock tick is ~42 ns and a push can cost less than that, so
// any p50 at one tick means "under one tick" and cannot be resolved further.
struct ClockFloor {
  uint64_t pair_p50_ns;
  uint64_t tick_ns;  // smallest nonzero delta observed == the counter's resolution
};

ClockFloor measure_clock_floor(size_t samples) {
  std::vector<uint32_t> v;
  v.reserve(samples);
  for (size_t i = 0; i < samples; i++) {
    const auto a = Clock::now();
    const auto b = Clock::now();
    v.push_back(static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count()));
  }
  std::sort(v.begin(), v.end());
  uint64_t tick = 0;
  for (uint32_t x : v)
    if (x != 0) { tick = x; break; }
  return ClockFloor{v[v.size() / 2], tick};
}

}  // namespace

int main() {
  // 1024 items is a realistic pipeline queue depth: at ~8 KiB per chunk it is ~8 MiB of
  // in-flight payload, the same order as SPEC 3.7's kCheckpointBytes, and small enough
  // that SPEC S10's bounded-memory claim still means something.
  constexpr size_t kCap = 1024;
  constexpr size_t kTotalItems = 1u << 20;  // ~1.05 M items per configuration

  const unsigned hw = std::thread::hardware_concurrency();
  std::printf("bench/queues -- SPEC R2.2 / 8.5\n");
  std::printf("hardware_concurrency = %u, queue depth = %zu, %zu items per configuration\n",
              hw, kCap, kTotalItems);
  const ClockFloor floor = measure_clock_floor(200000);
  std::printf("steady_clock: tick %llu ns, back-to-back read pair p50 %llu ns. Every p50\n"
              "below is quantised to that tick -- a p50 of one tick means \"under one\n"
              "tick\", not \"exactly one tick\".\n\n",
              static_cast<unsigned long long>(floor.tick_ns),
              static_cast<unsigned long long>(floor.pair_p50_ns));

  struct Config { size_t producers, consumers; };
  const Config configs[] = {{1, 1}, {2, 1}, {4, 1}, {8, 1},
                            {1, 2}, {2, 2}, {4, 2}, {8, 2}};

  std::printf("TABLE 1 -- identical non-blocking API and spin/yield policy for all three.\n");
  std::printf("           The only variable is the data structure.\n");
  {
    // SpscRing is single-producer/single-consumer by construction, so it appears once.
    SpscRing<Item, kCap> spsc;
    const Result r = run_try_api(spsc, 1, 1, kTotalItems);
    print_row("SpscRing", 1, 1, r);
  }
  std::vector<Result> t1_mpmc, t1_mutex, t3_mpmc, t3_mutex;
  for (const auto& c : configs) {
    MpmcQueue<Item> q(kCap);
    t1_mpmc.push_back(run_try_api(q, c.producers, c.consumers, kTotalItems / c.producers));
    print_row("MpmcQueue", c.producers, c.consumers, t1_mpmc.back());
  }
  for (const auto& c : configs) {
    MutexQueue<Item> q(kCap);
    t1_mutex.push_back(run_try_api(q, c.producers, c.consumers, kTotalItems / c.producers));
    print_row("mutex(try)", c.producers, c.consumers, t1_mutex.back());
  }

  std::printf("\nTABLE 2 -- the mutex queue as an engineer would actually write it:\n");
  std::printf("           blocking push/pop on two condition variables.\n");
  std::vector<Result> t2_mutex;
  for (const auto& c : configs) {
    MutexQueue<Item> q(kCap);
    t2_mutex.push_back(run_blocking(q, c.producers, c.consumers, kTotalItems / c.producers));
    print_row("mutex(block)", c.producers, c.consumers, t2_mutex.back());
  }

  // -------------------------------------------------------------------------
  // TABLE 3: the same comparison with the pipeline's real per-item cost present.
  // -------------------------------------------------------------------------
  //
  // This is the table that can retire the headline claim, so it is run last and reported
  // whatever it says. Tables 1 and 2 gave the producers nothing to do but push, which is
  // the maximum-contention regime and the one most flattering to a lock-free design.
  {
    const BurnCal cal = calibrate_burn(8.5);
    const uint64_t work_iters = cal.iters;
    // Far fewer items: at 8.5 us each, a million items would be 8.5 CPU-seconds per row.
    constexpr size_t kWorkItems = 1u << 16;
    std::printf("\nTABLE 3 -- with T1's real upstream cost restored: ~8.5 us of\n"
                "           chunk+SHA-256-equivalent work per item before each push\n"
                "           (%llu splitmix64 rounds = %.2f us re-measured), %zu items.\n"
                "           A throughput near %.0f K items/s per producer is the sign the\n"
                "           calibration landed; far above it means it did not.\n",
                static_cast<unsigned long long>(work_iters), cal.achieved_us, kWorkItems,
                1000.0 / cal.achieved_us);
    for (const auto& c : configs) {
      MpmcQueue<Item> q(kCap);
      t3_mpmc.push_back(run_try_api(q, c.producers, c.consumers,
                                    kWorkItems / c.producers, work_iters));
      print_row("MpmcQueue+w", c.producers, c.consumers, t3_mpmc.back());
    }
    for (const auto& c : configs) {
      MutexQueue<Item> q(kCap);
      t3_mutex.push_back(run_try_api(q, c.producers, c.consumers,
                                     kWorkItems / c.producers, work_iters));
      print_row("mutex+w", c.producers, c.consumers, t3_mutex.back());
    }
    std::printf("  (sink %llu -- printed only so the work cannot be optimised away)\n",
                static_cast<unsigned long long>(g_sink.load()));
  }

  // -------------------------------------------------------------------------
  // The verdict, computed from the rows above rather than written next to them.
  // -------------------------------------------------------------------------
  //
  // Prose in a benchmark goes stale the first time the hardware changes. These ratios are
  // derived from the numbers this run actually produced, so the conclusion cannot drift
  // away from the measurement -- which is the whole point of SPEC 8.5's rule that the
  // measurement decides the wording.
  std::printf("\nVERDICT -- lock-free MpmcQueue vs the mutex baseline, same harness\n");
  std::printf("  %-10s %-28s %-28s\n", "config",
              "TABLE 1 (queue is the work)", "TABLE 3 (+8.5 us upstream work)");
  std::printf("  %-10s %-28s %-28s\n", "", "thruput x   p99 x", "thruput x   p99 x");
  double worst_t3_thru = 1e9, best_t3_thru = 0, best_t3_p99 = 0;
  double worst_t1_thru = 1e9, best_t1_thru = 0;
  // Sums of logs, because the average of a set of RATIOS is the geometric mean, not the
  // arithmetic one: a config that is 2x better and one that is 2x worse should average to
  // 1.0, and arithmetically they average to 1.25. Which direction you happened to divide
  // should not decide a headline claim.
  double t1_thru_log = 0, t3_thru_log = 0, t3_p99_log = 0;
  for (size_t i = 0; i < std::size(configs); i++) {
    const double t1_thru = t1_mpmc[i].items_per_sec / t1_mutex[i].items_per_sec;
    const double t1_p99 = static_cast<double>(t1_mutex[i].p99_ns) /
                          static_cast<double>(t1_mpmc[i].p99_ns ? t1_mpmc[i].p99_ns : 1);
    const double t3_thru = t3_mpmc[i].items_per_sec / t3_mutex[i].items_per_sec;
    const double t3_p99 = static_cast<double>(t3_mutex[i].p99_ns) /
                          static_cast<double>(t3_mpmc[i].p99_ns ? t3_mpmc[i].p99_ns : 1);
    worst_t1_thru = std::min(worst_t1_thru, t1_thru);
    best_t1_thru = std::max(best_t1_thru, t1_thru);
    worst_t3_thru = std::min(worst_t3_thru, t3_thru);
    best_t3_thru = std::max(best_t3_thru, t3_thru);
    best_t3_p99 = std::max(best_t3_p99, t3_p99);
    t1_thru_log += std::log(t1_thru);
    t3_thru_log += std::log(t3_thru);
    t3_p99_log += std::log(t3_p99);
    std::printf("  %2zup/%zuc      %7.2fx   %7.2fx          %7.2fx   %7.2fx\n",
                configs[i].producers, configs[i].consumers, t1_thru, t1_p99, t3_thru,
                t3_p99);
  }
  const double n_cfg = static_cast<double>(std::size(configs));
  const double t1_thru_geo = std::exp(t1_thru_log / n_cfg);
  const double t3_thru_geo = std::exp(t3_thru_log / n_cfg);
  const double t3_p99_geo = std::exp(t3_p99_log / n_cfg);
  std::printf("  (>1.00x means the lock-free queue is better on that metric)\n");
  std::printf("  Table 3 summary: throughput %.2fx geomean (range %.2f-%.2fx), p99 %.1fx\n"
              "  geomean (best %.1fx). The GEOMEANS are the finding -- a single best or\n"
              "  worst row is one scheduling accident away from a different conclusion.\n",
              t3_thru_geo, worst_t3_thru, best_t3_thru, t3_p99_geo, best_t3_p99);

  // -------------------------------------------------------------------------
  // What the numbers mean for a 100 Mbit/s WAN link.
  // -------------------------------------------------------------------------
  //
  // The arithmetic, not an opinion: a 100 Mbit/s WAN link is 12.5 MB/s. At SPEC 3.3's
  // 8 KiB average chunk that is 12.5e6 / 8192 = ~1526 pipeline items per second.
  const double wan_mbps = 12.5;
  const double items_per_sec_wan = wan_mbps * 1e6 / 8192.0;
  const double upstream_us_per_item = 8192.0 / (966.0 * 1e6) * 1e6;

  // The MINIMUM over every row this run printed, ours and the baseline's, in all three
  // tables. It used to be `t3_mpmc[0]` -- the first Table 3 configuration -- printed under
  // the label "slowest row measured anywhere". That happens to be the slowest row on this
  // machine, and "happens to be" is not a measurement: on hardware where a different
  // configuration is the floor, the label would have been simply false, and the claim it
  // supports ("even our worst row outruns the WAN link by N times") is a claim about the
  // MINIMUM or it is nothing.
  double slowest_row = 1e300;
  for (const std::vector<Result>* table : {&t1_mpmc, &t1_mutex, &t2_mutex, &t3_mpmc,
                                           &t3_mutex}) {
    for (const Result& r : *table) slowest_row = std::min(slowest_row, r.items_per_sec);
  }
  std::printf("\nWHAT THIS MEANS FOR A 100 Mbit/s WAN LINK (SPEC 3.2, 8.5)\n");
  std::printf("  link rate                     : %.1f MB/s = %.0f items/s at 8 KiB chunks\n",
              wan_mbps, items_per_sec_wan);
  std::printf("  upstream cost per item (T1)   : %.2f us of chunk+SHA-256 at 966 MB/s\n",
              upstream_us_per_item);
  std::printf("  one core's item supply        : %.0f items/s -- %.0fx the WAN's demand\n",
              1e6 / upstream_us_per_item, (1e6 / upstream_us_per_item) / items_per_sec_wan);
  std::printf("  slowest row measured anywhere : %.0f items/s -- %.0fx the WAN's demand\n",
              slowest_row, slowest_row / items_per_sec_wan);
  // The reading below is ASSEMBLED FROM THE RATIOS THIS RUN PRODUCED, including the
  // adjectives. The previous version stated "two to four times faster", "the Table 3
  // ratios scatter around 1.0" and "the p99 advantage stays the widest gap in the table"
  // as fixed prose sitting underneath computed numbers -- which is precisely the drift
  // this file's header claims to have designed out. On a machine where Table 3 came back
  // at 2x, the numbers and the sentence under them would have disagreed, and the sentence
  // is the part that gets copied into BENCHMARKS.md and into the headline claims.
  //
  // Both booleans read the GEOMEAN, never the best row. An earlier draft of this fix
  // tested best_t3_thru < 1.25 and duly announced that the throughput advantage
  // "SURVIVES" off a spread of 0.75-1.75x -- a spread whose centre is 1.1x and which is
  // the definition of scattering around 1.0. Picking the extreme of a noisy sample is how
  // a computed verdict ends up less honest than the prose it replaced.
  const bool t3_advantage_drains = t3_thru_geo < 1.25;
  const bool tail_advantage_holds = t3_p99_geo > t3_thru_geo * 2.0;
  std::printf(
      "\n  Read Table 3, not Table 1. Table 1 says the lock-free MpmcQueue is %.1fx the\n"
      "  mutex baseline's throughput (geomean; range %.1f-%.1fx), and Table 1 is not this\n"
      "  pipeline: it gives a producer nothing to do but push, so the queue is 100%% of\n"
      "  the work and contention is at its theoretical maximum. Restore T1's real ~%.1f\n"
      "  us per item and the Table 3 throughput ratios centre on %.2fx (range %.2f-%.2fx)\n"
      "  -- %s\n",
      t1_thru_geo, worst_t1_thru, best_t1_thru, upstream_us_per_item, t3_thru_geo,
      worst_t3_thru, best_t3_thru,
      t3_advantage_drains
          ? "the throughput advantage\n  drains away, which is the signature of both queues"
            " being pinned by the\n  upstream CPU cost rather than by the queue, exactly as"
            " SPEC 8.5 predicted."
          : "the throughput advantage\n  SURVIVES the upstream work. SPEC 8.5 predicted it"
            " would not; the measurement\n  disagrees with the prediction and the"
            " measurement wins.");
  std::printf(
      "  Meanwhile the p99 advantage centres on %.1fx in Table 3, so the tail gap %s\n"
      "  the throughput gap. And the slowest row anywhere above still delivers %.0fx\n"
      "  what a 100 Mbit/s link can carry.\n",
      t3_p99_geo,
      tail_advantage_holds ? "clearly OUTLIVES" : "does not meaningfully outlive",
      slowest_row / items_per_sec_wan);
  std::printf(
      "\n  So the honest reading, given those numbers: %s\n",
      (t3_advantage_drains && tail_advantage_holds)
          ? "on this workload the lock-free\n  queues buy no throughput the link could ever"
            " use, and buy a bounded tail. The\n  headline claim should be a DESIGN claim --"
            " bounded-latency handoff, no producer\n  blocked by a descheduled peer, memory"
            " bounded by construction -- and NOT a\n  throughput claim. Quoting Table 1's"
            " ratio as a pipeline speedup would be true\n  of the benchmark and false of the"
            " system."
          : "the ratios above do not match the\n  pattern this benchmark was written"
            " expecting (throughput advantage gone, tail\n  advantage intact). Do not reuse"
            " the stock wording -- read the three tables and\n  write the claim from what"
            " they actually say, per SPEC 8.5.");
  return 0;
}
