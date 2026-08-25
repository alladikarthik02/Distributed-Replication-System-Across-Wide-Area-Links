// A bounded multi-producer / multi-consumer queue (Vyukov), for the fan-in and fan-out
// stages of the source pipeline: chunkers -> compressors -> sender (SPEC 3.6).
//
// WHY NOT JUST USE THE SPSC RING EVERYWHERE:
//   Because these stages are genuinely N-to-M. N chunker threads feed M compressor
//   threads; M compressors feed the one sender thread. The SPSC ring's whole trick is
//   that each index has exactly one writer, and that trick evaporates the moment two
//   producers exist. You could build N*M private SPSC rings and round-robin between them,
//   and that is a real design (it is how some schedulers work) -- rejected here because
//   it turns a full queue from a backpressure signal into a load-balancing problem: one
//   slow consumer stalls its private ring while the others sit idle, and the producer
//   cannot notice.
//
// THE DESIGN (Dmitry Vyukov's bounded MPMC queue) AND WHY IT IS THE RIGHT ONE:
//   An array of cells. Each cell carries its own std::atomic<size_t> sequence number
//   alongside the value. A producer CASes a global enqueue position to claim a ticket;
//   a consumer CASes a global dequeue position to claim one. The cell's sequence number
//   is then the handshake that says whose turn the cell is on:
//
//     cell.seq == pos       -> the cell is EMPTY and belongs to producer ticket `pos`
//     cell.seq == pos + 1   -> the cell is FULL  and belongs to consumer ticket `pos`
//     anything else         -> not our turn yet (or the queue is full/empty)
//
//   So exactly one CAS per operation on the shared position, plus one release store on
//   the cell. No lock, no allocation on the hot path, no node reclamation problem.
//
// WHY THE SEQUENCE COUNTERS MAKE ABA IMPOSSIBLE, NOT MERELY UNLIKELY (SPEC S9 -- this is
// the paragraph the design has to survive being asked about):
//   The classic ABA failure is a CAS that succeeds because a value returned to a previous
//   state while the thread was descheduled: read A, sleep, someone pops A and pushes B and
//   pushes A again, wake, CAS(A -> ...) succeeds against a completely different queue.
//   The standard mitigations are tag bits (a counter packed beside a pointer, which wraps
//   -- so ABA becomes rare, not impossible), hazard pointers, or epoch reclamation.
//   Here neither position nor sequence number ever decreases. A cell's sequence advances
//   0 -> 1 -> Cap -> Cap+1 -> 2*Cap -> ... one lap at a time, forever, and the positions
//   count tickets issued, never slots. For a stale `pos` to be accepted again, a
//   monotonically increasing 64-bit counter would have to return to a value it has already
//   passed, which requires 2^64 operations -- at one per nanosecond, ~584 years of
//   uninterrupted running. The state is never revisited, so there is no A to come back to.
//   That is a structural argument, not a probabilistic one, and it is the reason this
//   design needs no tag bits and no reclamation scheme at all.
//
//   (Note that on the CAS itself we can use relaxed ordering: the CAS only claims a
//   ticket. All the actual publication ordering rides on the CELL's acquire/release pair,
//   which is what synchronises the value with the thread that will read it.)
//
// CAPACITY IS ROUNDED UP TO A POWER OF TWO, not rejected, because the caller's natural
// number is a memory budget ("about 1024 items in flight"), not a protocol constant --
// and `pos & mask` must be a mask. It is also CLAMPED at kMaxCapacity before it is used
// to size anything, because an unvalidated size that feeds a shift and then an allocation
// is SPEC S7's hazard wearing a different hat: the unclamped version hung forever above
// 2^63 and std::terminate'd around 2^62. capacity() reports the value actually built --
// rounded and clamped -- so nobody has to guess which number the queue is using;
// tests/test_queues.cpp asserts both halves of that convention.
//
// BOUNDED, and the bound is the feature: SPEC S10. try_push returns false rather than
// growing or blocking, and the caller owns the backpressure policy -- see spsc_ring.h.
#pragma once

// Included for kCacheLine only. That constant is one measured platform fact (SPEC 2.5)
// and defining it twice is how two copies of a measurement drift apart. When a shared
// concurrency header appears it moves there; today these two files are the only users.
#include "wanrep/spsc_ring.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace wanrep {

template <class T>
class MpmcQueue {
  static_assert(std::is_move_constructible_v<T>, "the pipeline moves buffers, never copies");
  static_assert(std::is_move_assignable_v<T>, "try_pop assigns into the caller's slot");
  // NOTHROW, and this one is not tidiness -- it is the difference between a dropped item
  // and a permanently wedged queue. try_push_moving claims ticket `pos` by advancing
  // enqueue_pos_ and only then constructs into the cell. If that construction threw, the
  // ticket would already be spent and nothing would ever store seq == pos + 1: every
  // consumer that reached `pos` would read the cell as "not published yet" and report
  // EMPTY forever, and every producer arriving a lap later would read it as FULL forever.
  // The queue would be dead with no error anywhere. Handing the ticket back is not
  // possible (a later producer may already own pos + cap_), and result.h says plainly
  // that wanrep does not use exceptions, so nothing would catch one anyway. So the
  // requirement is enforced where it can still be repaired: at compile time. Every
  // payload the pipeline moves -- vectors, unique_ptrs, the handle structs -- already
  // satisfies it; a type that does not has no business on this hot path.
  static_assert(std::is_nothrow_move_constructible_v<T>,
                "MpmcQueue: a throwing move constructor would wedge the queue permanently "
                "-- the Vyukov ticket is spent before the value is published");

 public:
  // The largest number of cells this queue will ever allocate, and therefore the value
  // capacity() reports for any larger request. Public so a caller can range-check its own
  // configuration rather than discovering the clamp from a metric.
  //
  // WHY 2^20 AND NOT "whatever you asked for": at SPEC 3.3's ~8 KiB average chunk, a
  // million items in flight is ~8 GiB of payload -- three orders of magnitude past any
  // budget SPEC S10's bounded-memory claim could survive, and 1024x the depth
  // bench/queues actually runs the pipeline at. A request above this line is a sizing
  // bug, not a sizing decision.
  //
  // WHY THE CLAMP EXISTS AT ALL (SPEC S7's rule, applied to a caller-supplied size rather
  // than a wire-supplied one: range-check BEFORE the number is used to size anything).
  // Without it, `capacity` reached the rounding loop unvalidated and two things happened:
  //   capacity > 2^63  -> `p <<= 1` shifted the top bit out, p became 0, and `p < n` was
  //                       true forever. The constructor HUNG -- no error, no crash, no
  //                       output, the hardest failure shape there is to diagnose.
  //   capacity ~ 2^62  -> the loop finished and `new Cell[cap_]` threw std::bad_alloc,
  //                       which in an exception-free codebase (see result.h) is
  //                       std::terminate. A configuration typo became a silent abort.
  static constexpr size_t kMaxCapacity = size_t{1} << 20;
  static_assert((kMaxCapacity & (kMaxCapacity - 1)) == 0,
                "kMaxCapacity must be a power of two, or clamping breaks `pos & mask`");

  // `capacity` is rounded UP to a power of two, floored at 2 and capped at kMaxCapacity.
  // See the header comment; capacity() always reports what actually got built.
  explicit MpmcQueue(size_t capacity)
      : cap_(clamp_to_pow2(capacity)),
        mask_(cap_ - 1),
        cells_(new Cell[cap_]) {
    // Seeding cell i with sequence i is what makes the empty queue consistent with the
    // rule above: enqueue ticket 0 finds cell 0 with seq == 0, ticket 1 finds cell 1 with
    // seq == 1, and so on. Without this the first lap would deadlock at cell 1.
    for (size_t i = 0; i < cap_; i++) {
      cells_[i].seq.store(i, std::memory_order_relaxed);
    }
  }

  MpmcQueue(const MpmcQueue&) = delete;
  MpmcQueue& operator=(const MpmcQueue&) = delete;

  // Destroys whatever is still queued. Requires quiescence -- everything between the
  // dequeue and enqueue positions is a live value only if no producer is mid-push, and a
  // destructor racing a push is a lifetime bug the queue cannot fix.
  ~MpmcQueue() {
    const size_t enq = enqueue_pos_.load(std::memory_order_relaxed);
    for (size_t deq = dequeue_pos_.load(std::memory_order_relaxed); deq != enq; ++deq) {
      cells_[deq & mask_].value.~T();
    }
  }

  // Returns false when full, and on a false return the caller's item is untouched. See
  // spsc_ring.h's try_push for the full account of why this is `T&&` and not `T v`: the
  // by-value form consumed the caller's object at the call site, and the retry loop that
  // backpressure forces every caller to write then pushed an emptied husk on every
  // attempt after the first. This queue is the one protocol.h's send pipeline actually
  // uses, so that is where it bit -- chunk payloads delivered as zero bytes under load,
  // with the batch's scalar fields still correct so nothing downstream noticed.
  bool try_push(T&& v) { return try_push_moving(v); }

  // The same, for a NAMED item: moves out of `v` only on success, so one item can survive
  // any number of refused attempts. This is the form the pipeline's producers use.
  bool try_push_moving(T& v) {
    Cell* cell = nullptr;
    size_t pos = enqueue_pos_.load(std::memory_order_relaxed);
    for (;;) {
      cell = &cells_[pos & mask_];
      const size_t seq = cell->seq.load(std::memory_order_acquire);
      // Signed difference, so a wrapped position compares correctly against a wrapped
      // sequence: only the RELATIVE order matters and (a - b) as a signed value is the
      // standard way to ask "which came first" for monotonic counters.
      const Diff diff = static_cast<Diff>(seq) - static_cast<Diff>(pos);
      if (diff == 0) {
        // The cell is empty and it is our ticket. Claim the ticket; weak is fine because
        // a spurious failure just re-reads pos and retries.
        if (enqueue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
          break;
        }
      } else if (diff < 0) {
        // The cell is still holding the value from the previous lap: the consumer that
        // owns it has not run yet. That is exactly "full" -- and note this is a real
        // answer, not a retry, so a full queue costs one load, not a spin.
        return false;
      } else {
        // Another producer won this ticket and moved the position on. Re-read and retry.
        pos = enqueue_pos_.load(std::memory_order_relaxed);
      }
    }

    new (&cell->value) T(std::move(v));

    // The release store publishes the value: pos + 1 means "full, waiting for the
    // consumer holding ticket pos". Everything written above is visible to the consumer
    // that acquires this sequence number.
    cell->seq.store(pos + 1, std::memory_order_release);
    return true;
  }

  // Returns false when empty.
  bool try_pop(T& out) {
    Cell* cell = nullptr;
    size_t pos = dequeue_pos_.load(std::memory_order_relaxed);
    for (;;) {
      cell = &cells_[pos & mask_];
      const size_t seq = cell->seq.load(std::memory_order_acquire);
      const Diff diff = static_cast<Diff>(seq) - static_cast<Diff>(pos + 1);
      if (diff == 0) {
        if (dequeue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
          break;
        }
      } else if (diff < 0) {
        // The producer holding this ticket has claimed the cell but not yet published --
        // or never claimed it. Either way there is nothing for us: empty.
        return false;
      } else {
        pos = dequeue_pos_.load(std::memory_order_relaxed);
      }
    }

    out = std::move(cell->value);
    cell->value.~T();

    // pos + mask_ + 1 == pos + cap_: the sequence number this cell will need when the
    // producer one full lap later comes back to it. Written as mask_ + 1 rather than cap_
    // to keep the "advance exactly one lap" arithmetic beside the mask it is derived from.
    cell->seq.store(pos + mask_ + 1, std::memory_order_release);
    return true;
  }

  // The ROUNDED capacity -- what the queue will actually hold, not what was asked for.
  size_t capacity() const { return cap_; }

  // Exposed for the same reason as SpscRing's: the padding is a performance property with
  // no behavioural signature, so a test asserts it rather than trusting the alignas.
  uintptr_t enqueue_pos_addr() const { return reinterpret_cast<uintptr_t>(&enqueue_pos_); }
  uintptr_t dequeue_pos_addr() const { return reinterpret_cast<uintptr_t>(&dequeue_pos_); }

 private:
  using Diff = std::make_signed_t<size_t>;

  struct Cell {
    std::atomic<size_t> seq;
    // Anonymous union: as in SpscRing, so T need not be default-constructible and an
    // empty cell holds no live object rather than a moved-from one.
    union {
      T value;
    };
    Cell() : seq(0) {}
    ~Cell() {}
    Cell(const Cell&) = delete;
    Cell& operator=(const Cell&) = delete;
  };

  // The clamp happens BEFORE the rounding loop, which is precisely where the old failure
  // lived: with `n` above the largest representable power of two there is no power of two
  // to round up to, `p <<= 1` reaches 0, and `while (p < n)` never terminates. Bounding
  // `n` first makes the loop's termination a property of the code rather than a property
  // of the argument -- and guarantees cap_ * sizeof(Cell) stays nowhere near overflowing.
  static constexpr size_t clamp_to_pow2(size_t n) {
    if (n < 2) return 2;                          // a capacity-1 MPMC queue is a handoff
    if (n >= kMaxCapacity) return kMaxCapacity;   // and kMaxCapacity is already a power of two
    size_t p = 2;
    while (p < n) p <<= 1;  // terminates: n < kMaxCapacity, so p reaches it at the latest
    return p;
  }

  const size_t cap_;
  const size_t mask_;
  std::unique_ptr<Cell[]> cells_;

  // The two positions are written by every producer and every consumer respectively. On
  // one cache line they would collide across the whole pipeline -- see spsc_ring.h for
  // why 64 is the number (SPEC 2.5). The leading alignas also keeps them off the line
  // holding cap_/mask_/cells_, which every operation READS on every call: a hot read-only
  // line sharing with a hot written line is the same bug wearing a different hat.
  alignas(kCacheLine) std::atomic<size_t> enqueue_pos_{0};
  alignas(kCacheLine) std::atomic<size_t> dequeue_pos_{0};
  // Trailing pad, so whatever the embedding object places after this queue cannot land on
  // dequeue_pos_'s line.
  char pad_tail_[kCacheLine]{};
};

}  // namespace wanrep
