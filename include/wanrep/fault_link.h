// Deliberate transport failures at named injection points (SPEC 3.8, R3.1, R3.2).
//
// WHY A LINK WRAPPER RATHER THAN "unplug the cable and see what happens":
//   R3.2 requires that a link drop be tested at EVERY protocol phase -- during HELLO,
//   mid-manifest, after NEED, mid-payload, between the last chunk and the commit, between
//   the commit and its ACK. Those are moments in a state machine, not moments on a clock,
//   and the only way to hit them reliably is to let the code under test tell the injector
//   where it is. FaultLink is the transport half of that: fault.h names the points, the
//   protocol code visits them, and this class turns a visit into a real socket failure
//   that is indistinguishable to the peer from a machine that died.
//
// THE THREE KINDS, AND WHY EACH ONE IS A DIFFERENT TEST:
//   * kDropLink  -> the peer must observe an ABRUPT close: ECONNRESET, i.e. Err::kReset.
//     Not a FIN. T0 measured that a FIN reads as 0 and an RST reads as ECONNRESET (SPEC
//     2.5), and SPEC 3.7's resume logic branches on precisely that difference: a peer
//     that says kClosed has finished, and treating a dead peer's silence as "finished"
//     would commit a truncated transfer as complete (S5). Injecting a clean close here
//     would therefore test the OPPOSITE of the thing that needs proving.
//   * kIoError   -> Err::kFaultInjected on the current operation, link still alive. This
//     is the "the syscall failed but the connection is fine" case that S11 says must
//     surface as an error rather than a hang or a silent short transfer.
//   * kCorrupt   -> one bit flipped in the bytes crossing the link. Not because TCP
//     checksums fail often (they rarely do) but because the frame CRCs of SPEC 3.2 are a
//     claim this project makes, and an untested check is not a check.
//
// WHY THE ABRUPT CLOSE IS A DOWNCAST:
//   `Link` (T0, link.h) has no abortive-close in its interface, and this task may not
//   modify shared headers. So `abort_link()` below downcasts to the implementations that
//   do provide one -- TcpLink and MemoryLink -- and unwraps WanLink to reach whatever it
//   wraps. If the inner link is none of those, the drop degrades to an orderly close and
//   says so through `drop_was_degraded()`, because a fault that silently became a
//   DIFFERENT fault would make the matrix in R3.2 report coverage it does not have.
//   Adding `virtual void close_abruptly()` to Link would be the cleaner fix and is noted
//   as such.
//
// WHICH THREAD THE DROP RUNS ON, AND WHAT THAT COSTS:
//   set_drop_after_bytes() counts bytes in BOTH directions, and SPEC 3.6 puts a sender
//   thread and a reader thread on the same socket -- so the byte that trips the drop may
//   arrive on the reader's thread while the sender is inside ::send() on that same
//   descriptor. The abortive close then releases a descriptor another thread is using.
//   TcpLink narrows that window as far as a socket wrapper can (see its threading
//   contract) and TSan still reports the residue, correctly: closing a descriptor out from
//   under a blocked syscall is not something this layer can make safe. It is accepted here
//   because it is exactly the event being emulated -- a machine that died mid-transfer does
//   not wait for its peer's threads to reach a quiet point -- and because the alternative,
//   waking the blocked thread with shutdown(), sends the peer a FIN and would turn every
//   injected drop into the orderly close this class exists NOT to produce.
//   The consequence that IS handled: an operation caught in that window can come back
//   kClosed, and after a deliberate drop kClosed is a lie the resume logic would act on --
//   see as_reset_if_dropped().
//
// REJECTED: injecting drops by randomly closing the socket from a timer thread. It finds
//   bugs but proves nothing -- "we killed it at random and it seemed fine" is not a claim
//   anyone can check or replay. R3.5 wants `--case <id> --seed <n>` to reproduce a
//   failure exactly, so faults fire at named points and at byte counts, both of which are
//   deterministic functions of the run.
#pragma once

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "wanrep/fault.h"
#include "wanrep/link.h"
#include "wanrep/result.h"
#include "wanrep/tcp_link.h"
#include "wanrep/wan_link.h"

namespace wanrep {

// Closes `link` so the PEER sees a reset rather than a clean end-of-stream. Returns false
// if the concrete link had no abortive close and the call degraded to an orderly one.
// Recursive through WanLink so FaultLink(WanLink(TcpLink)) -- the normal stack for a
// fault test over an emulated WAN -- still produces a real RST.
inline bool abort_link(const std::shared_ptr<Link>& link) {
  if (auto* t = dynamic_cast<TcpLink*>(link.get())) {
    t->close_abruptly();
    return true;
  }
  if (auto* m = dynamic_cast<MemoryLink*>(link.get())) {
    m->close_abruptly();
    return true;
  }
  if (auto* w = dynamic_cast<WanLink*>(link.get())) {
    return abort_link(w->inner());
  }
  link->close();
  return false;
}

class FaultLink : public Link {
 public:
  // `plan` may be null, which means "nothing is ever armed" -- the production
  // configuration, and the case the transparency test pins down.
  FaultLink(std::shared_ptr<Link> inner, FaultPlan* plan, FaultPoint point)
      : inner_(std::move(inner)), plan_(plan), point_(point) {}

  // Fire a drop once this many bytes have crossed this link in either direction.
  //
  // Byte-counted rather than time-counted because SPEC R2.4 asks for a drop at a
  // RANDOMIZED OFFSET inside the payload phase and then asserts a bound on how much gets
  // re-sent. An offset is reproducible from a seed; a moment in time is not, and a
  // resume test that cannot be replayed is a test that cannot be debugged (S15).
  // 0 means "never", not "immediately": it is the disabled state, so a caller that
  // computed an offset of zero from a seed gets a link with no drop rather than one that
  // dies on its first byte.
  void set_drop_after_bytes(uint64_t n) { drop_after_.store(n, std::memory_order_relaxed); }

  Result<size_t> write_some(const uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    if (dropped_.load(std::memory_order_acquire)) {
      return err(Err::kReset, "link was dropped by fault injection");
    }
    switch (check()) {
      case FaultKind::kDropLink:
        do_drop();
        return err(Err::kReset, std::string("injected drop at ") + to_string(point_));
      case FaultKind::kIoError:
        return err(Err::kFaultInjected, std::string("injected write error at ") + to_string(point_));
      case FaultKind::kCorrupt:
        // Arm the flip at the midpoint of the buffer the caller offered. It is an OFFSET,
        // not an index into one call's buffer, because the write below may come back
        // short -- see write_corrupted().
        corrupt_at_.store(n / 2, std::memory_order_relaxed);
        break;
      case FaultKind::kKillSelf:
        // The kill -9 case, from the inside: no destructors, no flush, no FIN. The peer
        // sees an RST from the kernel reaping the socket, which is exactly what R3.3's
        // externally-killed target looks like. 137 == 128 + SIGKILL, the shell's
        // convention, so a runner reading the exit code sees the same number either way.
        ::_exit(137);
      case FaultKind::kStall:
        std::this_thread::sleep_for(std::chrono::milliseconds(kStallMs));
        break;
      case FaultKind::kNone:
        break;
    }
    // A corruption stays armed until the flipped byte has actually crossed the wire, so
    // this is checked on every write rather than only on the one that fired the point.
    if (corrupt_at_.load(std::memory_order_relaxed) != kNoCorrupt) return write_corrupted(p, n);
    auto r = inner_->write_some(p, n);
    // Same check on the write side, where an over-report is not a memory error here but a
    // silent truncation upstairs: write_all() would advance its cursor past bytes that
    // never went out, which is precisely the failure SPEC S11 exists to make impossible.
    if (r.ok() && *r > n) {
      return err(Err::kIo, "inner link reported more bytes than it was asked for");
    }
    if (r.ok()) account(*r);
    return as_reset_if_dropped(r);
  }

  Result<size_t> read_some(uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    if (dropped_.load(std::memory_order_acquire)) {
      return err(Err::kReset, "link was dropped by fault injection");
    }
    switch (check()) {
      case FaultKind::kDropLink:
        do_drop();
        return err(Err::kReset, std::string("injected drop at ") + to_string(point_));
      case FaultKind::kIoError:
        return err(Err::kFaultInjected, std::string("injected read error at ") + to_string(point_));
      case FaultKind::kCorrupt: {
        // SPEC 3.8 describes corruption on the write side; the read side is the same
        // event observed from the other end (a byte that changed in flight), and having
        // both means a point armed on either node exercises the frame CRCs.
        auto r = inner_->read_some(p, n);
        if (!r.ok()) return r;
        // `*r` came from another Link and is about to INDEX the caller's buffer. An
        // over-report would write past the end of it -- so the count is checked before it
        // is used as an index, which is SPEC S7's rule applied one layer down.
        if (*r > n) {
          return err(Err::kIo, "inner link reported more bytes than it was asked for");
        }
        if (*r > 0) {
          p[*r / 2] ^= 0x01;
          account(*r);
        }
        return r;
      }
      case FaultKind::kKillSelf:
        ::_exit(137);
      case FaultKind::kStall:
        std::this_thread::sleep_for(std::chrono::milliseconds(kStallMs));
        break;
      case FaultKind::kNone:
        break;
    }
    auto r = inner_->read_some(p, n);
    if (r.ok() && *r > n) {
      return err(Err::kIo, "inner link reported more bytes than it was asked for");
    }
    if (r.ok()) account(*r);
    return as_reset_if_dropped(r);
  }

  void close() override { inner_->close(); }

  bool is_open() const override {
    return !dropped_.load(std::memory_order_acquire) && inner_->is_open();
  }

  // Delegated for the same reason WanLink delegates: SPEC 4.1 makes bytes_out the
  // authoritative wire-byte counter, and a wrapper that kept its own would report bytes
  // the injector counted rather than bytes the transport moved. `bytes_through()` is the
  // wrapper's own counter and exists only to drive set_drop_after_bytes().
  uint64_t bytes_out() const override { return inner_->bytes_out(); }
  uint64_t bytes_in() const override { return inner_->bytes_in(); }

  std::string describe() const override {
    return std::string("fault[") + to_string(point_) + "]/" + inner_->describe();
  }

  uint64_t bytes_through() const { return moved_.load(std::memory_order_relaxed); }
  bool dropped() const { return dropped_.load(std::memory_order_acquire); }

  // True when a drop had to degrade to an orderly close because the inner link offered no
  // abortive one. A test asserting "the peer saw kReset" must fail loudly rather than
  // quietly measure a FIN, so this is exposed rather than logged.
  bool drop_was_degraded() const { return degraded_.load(std::memory_order_acquire); }

  const std::shared_ptr<Link>& inner() const { return inner_; }

 private:
  // How long kStall parks the operation. Long enough to open a real window for a
  // concurrent operation to interleave, short enough that a whole matrix of stalled cases
  // still finishes inside a test run.
  static constexpr int kStallMs = 50;

  // "No corruption armed". A sentinel rather than a second bool so the whole state is one
  // atomic word: the pending offset and the fact that one is pending cannot disagree.
  static constexpr uint64_t kNoCorrupt = ~uint64_t{0};

  FaultKind check() {
    if (plan_ == nullptr) return FaultKind::kNone;
    return plan_->check(point_);
  }

  // An operation that was ALREADY inside the transport when the drop fired comes back with
  // whatever the transport saw, and on the losing side of that race it can be kClosed --
  // the descriptor was taken away underneath it. Reporting kClosed for a link this
  // injector deliberately killed would be the single most dangerous mistranslation in the
  // project: SPEC 3.7 reads kClosed as "the peer finished", so a resume would treat a
  // truncated transfer as a complete one and commit it (SPEC 2.5, S5). The injector knows
  // better than the transport here, because it is the one that pulled the plug.
  Result<size_t> as_reset_if_dropped(Result<size_t> r) {
    if (!r.ok() && r.error().code == Err::kClosed &&
        dropped_.load(std::memory_order_acquire)) {
      return err(Err::kReset, "link was dropped by fault injection");
    }
    return r;
  }

  // The caller's buffer is const and may be a frame this node still needs intact, so the
  // corruption is applied to a COPY. Flipping one bit in the middle rather than replacing
  // a range on purpose: a single-bit error is the hardest case for a checksum, and CRC32C
  // is chosen in SPEC 3.2 precisely because it catches every one of them at these
  // lengths. If the frame check ever silently weakened to something like a sum, this is
  // the test that would notice.
  //
  // WHY THE TARGET IS AN OFFSET THAT SURVIVES ACROSS CALLS -- this was a real bug, found
  // by injecting corruption through a transport that short-writes:
  //   The flip goes at the midpoint, and SPEC 2.5's headline socket fact is that a write
  //   moves fewer bytes than it was given (this suite measures 57 344 of 4 194 304). When
  //   the inner link accepts fewer than half the buffer, the flipped byte is simply never
  //   transmitted -- and write_all's next call resends the tail from the caller's
  //   UNTOUCHED buffer. The point fired, fire_count() said 1, and nothing on the wire was
  //   ever wrong: a fault that silently became no fault, which is exactly what
  //   drop_was_degraded() exists to prevent for the other injection kind. A corrupt test
  //   that "passed" that way would be certifying the frame CRCs against a clean stream.
  //   So the target is remembered as a byte offset from where the corruption was armed,
  //   decremented by whatever each short write actually moved, and only spent once the
  //   flipped byte is inside the accepted count. The same original byte gets corrupted,
  //   however many calls it takes.
  Result<size_t> write_corrupted(const uint8_t* p, size_t n) {
    const uint64_t target = corrupt_at_.load(std::memory_order_relaxed);
    // Clamp for the case where the caller does NOT continue the interrupted buffer (only
    // write_all guarantees that): the flip then lands on the last byte offered rather
    // than out of bounds. n >= 1 here -- write_some rejects n == 0 before this point.
    const size_t idx = static_cast<size_t>(std::min<uint64_t>(target, n - 1));
    std::vector<uint8_t> tmp(p, p + n);
    tmp[idx] ^= 0x01;
    auto r = inner_->write_some(tmp.data(), tmp.size());
    if (r.ok()) {
      corrupt_at_.store(*r > idx ? kNoCorrupt : target - *r, std::memory_order_relaxed);
      account(*r);
    }
    return r;
  }

  void account(size_t k) {
    const uint64_t total = moved_.fetch_add(k, std::memory_order_relaxed) + k;
    const uint64_t threshold = drop_after_.load(std::memory_order_relaxed);
    if (threshold != 0 && total >= threshold && !dropped_.load(std::memory_order_acquire)) {
      // Note the ordering: the bytes are reported to the caller as sent, and THEN the
      // link is reset. An RST discards whatever is still queued in the kernel, so some of
      // those bytes may never arrive -- which is not a flaw in the injector, it is the
      // definition of the failure being injected. A node that dies mid-transfer leaves
      // the sender believing it sent more than the receiver believes it received, and
      // reconciling exactly that gap is what SPEC 3.7's resume is for.
      do_drop();
    }
  }

  void do_drop() {
    bool expected = false;
    if (!dropped_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
      return;  // exactly once, even if two threads reach a point at the same instant
    }
    if (!abort_link(inner_)) degraded_.store(true, std::memory_order_release);
  }

  std::shared_ptr<Link> inner_;
  FaultPlan* plan_ = nullptr;
  FaultPoint point_ = FaultPoint::kNone;

  // The offset, from where the corruption was armed, of the byte still to be flipped.
  // Atomic so that a concurrent reader of this object cannot race on it, though SPEC 3.6
  // gives the write side of a link to exactly one sender thread.
  std::atomic<uint64_t> corrupt_at_{kNoCorrupt};

  std::atomic<uint64_t> moved_{0};
  std::atomic<uint64_t> drop_after_{0};
  std::atomic<bool> dropped_{false};
  std::atomic<bool> degraded_{false};
};

}  // namespace wanrep
