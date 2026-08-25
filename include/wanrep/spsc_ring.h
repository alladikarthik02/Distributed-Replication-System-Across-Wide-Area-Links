// A bounded single-producer / single-consumer ring: the cheapest correct queue that
// exists, and the first stage of the source pipeline (SPEC 3.6).
//
// WHY A QUEUE AT ALL, AND WHY BOUNDED:
//   The pipeline is scanner -> chunker+hasher x N -> compressor x M -> sender. Stages run
//   at different speeds, so something has to absorb the difference. It must be BOUNDED,
//   because an unbounded queue turns a fast producer into unbounded memory growth -- and
//   SPEC S10 requires memory to stay bounded independently of dataset size. A full queue
//   is not a failure mode here, it is the backpressure mechanism, which is why try_push
//   returns false instead of growing or blocking: the queue reports the condition and the
//   CALLER decides the policy (spin, then block on a condvar). Putting the blocking
//   inside the queue would make every push pay for a policy most pushes do not need.
//
// WHY A SEPARATE SPSC TYPE WHEN WE ALREADY HAVE AN MPMC ONE (mpmc_queue.h):
//   Because scanner -> chunker is genuinely one-to-one, and knowing that removes the
//   compare-exchange entirely. The producer owns the head, the consumer owns the tail,
//   and neither ever needs to atomically claim a slot from a competitor: one release
//   store and one acquire load move an item. The MPMC queue needs a CAS on each side
//   because multiple threads contend for the same position. Using the MPMC queue here
//   would work and would be slower for no reason. Both are ~100 lines; the duplication
//   is cheap and the specialization is the point.
//
// REJECTED ALTERNATIVES:
//   * std::queue + std::mutex + condvar. The honest baseline, and bench/bench_queues.cpp
//     measures against it rather than assuming it loses (SPEC 8.5 predicts it may not).
//     Rejected as the default for a property the mutex cannot give: a producer here can
//     never be blocked by a consumer that got descheduled while holding a lock.
//   * boost::lockfree::spsc_queue / any third-party queue. SPEC 1 forbids hidden
//     dependencies, and a queue whose memory ordering we did not write is a queue whose
//     correctness argument we cannot make out loud.
//   * A wrapped read/write index pair (indices reset to 0 at Cap). Then "full" and
//     "empty" are the same state (head == tail) unless you waste a slot or carry a
//     separate count. Monotonic counters masked only at access time make the
//     distinction free: size == head - tail, always, and full is size == Cap.
//     They wrap at 2^64, which at one item per nanosecond is ~584 years.
//
// THE CACHE-LINE RULE (this is the part that is easy to get wrong and invisible when you
// do): SPEC 2.5 measured _SC_LEVEL1_DCACHE_LINESIZE == 64 bytes on the target platform.
// If head and tail share one line, every producer store to head invalidates the
// consumer's copy of tail and vice versa -- the two threads ping-pong an exclusive line
// between cores on EVERY item. That costs more than the mutex this queue exists to
// replace, and the code still looks correct. So each index sits alone on its own line,
// and tests/test_queues.cpp asserts the byte distance rather than trusting the alignas.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>

namespace wanrep {

// SPEC 2.5, measured not assumed. Deliberately NOT
// std::hardware_destructive_interference_size: on GCC that constant is an ABI-fragile
// compile-time guess about an unknown target, and we have a number from the actual
// machine this project is measured on.
inline constexpr size_t kCacheLine = 64;

// Cap is a template parameter, not a constructor argument, so the mask is a compile-time
// constant and the ring needs no heap allocation at all. The pipeline's queue depths are
// known at build time, so nothing is lost.
template <class T, size_t Cap>
class SpscRing {
  static_assert(Cap >= 2, "a capacity-1 ring is a handoff, not a pipeline buffer");
  static_assert((Cap & (Cap - 1)) == 0, "Cap must be a power of two: index = pos & mask");
  static_assert(std::is_move_constructible_v<T>, "the pipeline moves buffers, never copies");
  static_assert(std::is_move_assignable_v<T>, "try_pop assigns into the caller's slot");

 public:
  SpscRing() = default;

  // Non-copyable and non-movable: the queue's identity is shared between exactly two
  // threads, and moving it out from under either of them has no meaning.
  SpscRing(const SpscRing&) = delete;
  SpscRing& operator=(const SpscRing&) = delete;

  // Destroys whatever is still queued. Only safe once both threads are done with it --
  // which is true by construction, since a destructor running concurrently with a push
  // is already a lifetime bug that no queue can defend against.
  ~SpscRing() {
    const size_t head = head_.load(std::memory_order_relaxed);
    for (size_t tail = tail_.load(std::memory_order_relaxed); tail != head; ++tail) {
      slots_[tail & kMask].value.~T();
    }
  }

  // Returns false when full, and on a false return THE CALLER STILL OWNS ITS ITEM intact.
  // That property is the reason the parameter is an rvalue reference and not a by-value
  // sink, and it was learned the expensive way.
  //
  // This used to read `try_push(T v)`. A by-value sink consumes the caller's object at the
  // CALL SITE, so `while (!q.try_push(std::move(buf))) {}` -- the loop every caller writes
  // for backpressure -- moved `buf` into the parameter on attempt one and destroyed it
  // there, and every retry after that pushed a moved-from husk. That was documented here
  // in capital letters, with try_push_moving() offered beside it as the safe form, and the
  // very first consumer of this header (protocol.h's push_blocking) wrote the forbidden
  // loop anyway: a 4096-byte chunk payload arrived as 0 bytes, with the scalar fields
  // still intact so nothing downstream could tell -- and only when the queue was full.
  // The conclusion is not "document it harder". An interface whose obvious use is the
  // wrong use is the defect, and `T&&` binds without consuming, so the obvious loop is now
  // the correct one. Pinned by tests/test_queues.cpp,
  // a_refused_push_does_not_consume_the_callers_item.
  //
  // What the change costs: an LVALUE can no longer be pushed by an implicit copy. That is
  // not a loss -- the static_asserts above already say this queue moves buffers and never
  // copies them, and a caller holding a named object wants try_push_moving below.
  bool try_push(T&& v) { return try_push_moving(v); }

  // The same guarantee for a NAMED item: moves out of `v` only when the push succeeds, so
  // a producer can hold one item across any number of failed attempts without rebuilding
  // it. Two entry points rather than one only because C++ needs two spellings to bind
  // rvalues and lvalues; both are backpressure-safe, which is the point.
  bool try_push_moving(T& v) {
    const size_t head = head_.load(std::memory_order_relaxed);  // we are the only writer

    // The common case must not read the consumer's cache line at all. cached_tail_ is a
    // producer-private lower bound on the real tail: the tail only ever moves FORWARD, so
    // a stale value can say "full" when we are not, but never "space" when we are full.
    // We pay for the shared load only when the cache says we are out of room.
    if (head - cached_tail_ == Cap) {
      // Acquire pairs with the consumer's release store below. Beyond publishing the
      // index, it is what makes the consumer's destruction of the slot we are about to
      // reuse happen-before our construction into it.
      cached_tail_ = tail_.load(std::memory_order_acquire);
      if (head - cached_tail_ == Cap) return false;  // genuinely full: backpressure
    }

    new (&slots_[head & kMask].value) T(std::move(v));

    // The release store is the publish. Everything written to the slot above is visible
    // to any thread that acquires this value -- and nothing below it can be hoisted above
    // it, which is the guarantee that stops the consumer from reading a half-built item.
    head_.store(head + 1, std::memory_order_release);
    return true;
  }

  // Returns false when empty. Moves the item out and destroys the slot before releasing
  // it, so the producer that reuses the slot never overwrites a live object.
  bool try_pop(T& out) {
    const size_t tail = tail_.load(std::memory_order_relaxed);  // we are the only writer

    if (tail == cached_head_) {
      cached_head_ = head_.load(std::memory_order_acquire);
      if (tail == cached_head_) return false;  // genuinely empty
    }

    T* slot = &slots_[tail & kMask].value;
    out = std::move(*slot);
    slot->~T();

    // Release, so the producer's acquire of tail_ sees the destructor as complete before
    // it constructs into the same storage.
    tail_.store(tail + 1, std::memory_order_release);
    return true;
  }

  size_t capacity() const { return Cap; }

  // APPROXIMATE on purpose, and named so no caller can forget. Two separate atomic loads
  // cannot be taken atomically together, so by the time the second returns the first is
  // history. Useful for a metric or a log line; never for a control decision -- the only
  // sound decisions are "try_push said false" and "try_pop said false".
  //
  // "Approximate" means STALE, and it must not be allowed to mean WRONG. The guarantee
  // this function makes, and the reason for the two lines below, is that the answer is
  // always in [0, capacity()].
  size_t size_approx() const {
    // TAIL FIRST, then head, and the order is the entire correctness of this function.
    // Both indices only ever move forward, so reading the SUBTRAHEND first pins a lower
    // bound: head_ read afterwards is >= the tail we already have, and the difference
    // cannot go negative. Reading head first -- which is what this did -- lets the
    // consumer advance tail past our head snapshot in between, and since the difference
    // is size_t the result is not slightly stale, it is 18446744073709551615. Measured on
    // a busy capacity-2 ring: 465 such readings in 105 million.
    const size_t tail = tail_.load(std::memory_order_acquire);
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t depth = head - tail;

    // Clamped as well, because ordering alone is not enough: head_ can be read a full lap
    // after tail_, so the honest difference can exceed Cap even with no bug anywhere. A
    // depth gauge guaranteed to lie within the bound it is measuring is one a caller can
    // multiply by an item size for an S10 memory estimate; one that can exceed its own
    // capacity is not.
    return depth > Cap ? Cap : depth;
  }

  bool empty() const { return size_approx() == 0; }

  // Exposed so the cache-line separation above can be ASSERTED by a test rather than
  // assumed from the alignas. A silently-broken alignas would cost throughput and change
  // no behaviour, which is exactly the kind of bug that survives code review forever.
  uintptr_t head_addr() const { return reinterpret_cast<uintptr_t>(&head_); }
  uintptr_t tail_addr() const { return reinterpret_cast<uintptr_t>(&tail_); }

 private:
  static constexpr size_t kMask = Cap - 1;

  // A union, not a T array: T need not be default-constructible (a pipeline item that can
  // only be built from real data should not be forced to invent an empty state), and an
  // empty slot holds no live object at all rather than a moved-from husk.
  union Slot {
    Slot() {}
    ~Slot() {}
    Slot(const Slot&) = delete;
    Slot& operator=(const Slot&) = delete;
    T value;
  };

  // Four separate lines. head_ and tail_ must not share, for the reason in the file
  // header; the two caches must not share with the atomic the OTHER thread reads either,
  // or writing the cache would invalidate that thread's copy of the index and we would
  // have moved the ping-pong rather than removed it.
  alignas(kCacheLine) std::atomic<size_t> head_{0};   // producer writes, consumer reads
  alignas(kCacheLine) size_t cached_tail_{0};         // producer-private
  alignas(kCacheLine) std::atomic<size_t> tail_{0};   // consumer writes, producer reads
  alignas(kCacheLine) size_t cached_head_{0};         // consumer-private

  // The slots are NOT padded to a line each. Adjacent slots can false-share when the ring
  // is nearly empty or nearly full, and that is the residual cost we accept: padding a
  // 4096-slot ring to 64 B per slot would cost 256 KiB of cache footprint to avoid a
  // transient that only occurs when the pipeline is already stalled.
  alignas(kCacheLine) Slot slots_[Cap];
};

}  // namespace wanrep
