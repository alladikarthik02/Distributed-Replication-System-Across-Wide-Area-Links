// Named fault injection (SPEC 3.8, R3.1, R3.5).
//
// WHY NAMED POINTS AND NOT RANDOM FAILURES:
//   "We killed it at random offsets and it seemed fine" is not a claim anyone can check.
//   R3.1 requires that every fault has an ID, that the matrix of IDs is enumerable, and
//   that any failure is replayable by `--case <id> --seed <n>`. Random fault injection
//   finds bugs; NAMED fault injection proves coverage. We want both, so the offsets
//   inside a phase are randomized while the phase itself is a named point.
//
// WHY A GLOBAL PLAN:
//   The interesting injection points are deep inside the store's commit sequence -- between
//   the manifest fsync and the COMMIT record, between the COMMIT record and its ACK. Threading
//   a plan pointer through every layer to reach them would distort the production code far
//   more than a global whose fast path is one relaxed atomic load and which is compiled to a
//   no-op check in the normal case. The fast path costs a predictable-branch load; the slow
//   path takes a mutex and is only reached when a point is actually armed.
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

namespace wanrep {

// Every point at which a fault can be injected. Adding one here adds a row to the test
// matrix; the matrix is generated from this enum so it cannot drift out of date.
enum class FaultPoint : uint8_t {
  kNone = 0,
  kAfterHello,
  kMidManifest,
  kAfterManifest,
  kAfterNeed,
  kMidPayloadEarly,
  kMidPayloadLate,
  kBeforeCommit,
  kAfterChunkFsyncBeforeManifest,
  kAfterManifestFsyncBeforeCommit,  // the sharpest one: manifest durable, not yet visible
  kAfterCommitBeforeAck,            // committed but the source does not know it
  kMidResumeHandshake,
  kOnCheckpointWrite,
  kCount
};

inline constexpr size_t kFaultPointCount = static_cast<size_t>(FaultPoint::kCount);

inline const char* to_string(FaultPoint p) {
  switch (p) {
    case FaultPoint::kNone: return "none";
    case FaultPoint::kAfterHello: return "after_hello";
    case FaultPoint::kMidManifest: return "mid_manifest";
    case FaultPoint::kAfterManifest: return "after_manifest";
    case FaultPoint::kAfterNeed: return "after_need";
    case FaultPoint::kMidPayloadEarly: return "mid_payload_early";
    case FaultPoint::kMidPayloadLate: return "mid_payload_late";
    case FaultPoint::kBeforeCommit: return "before_commit";
    case FaultPoint::kAfterChunkFsyncBeforeManifest: return "after_chunk_fsync_before_manifest";
    case FaultPoint::kAfterManifestFsyncBeforeCommit: return "after_manifest_fsync_before_commit";
    case FaultPoint::kAfterCommitBeforeAck: return "after_commit_before_ack";
    case FaultPoint::kMidResumeHandshake: return "mid_resume_handshake";
    case FaultPoint::kOnCheckpointWrite: return "on_checkpoint_write";
    case FaultPoint::kCount: return "count";
  }
  return "?";
}

// What happens when a point fires.
enum class FaultKind : uint8_t {
  kNone = 0,
  kDropLink,   // abruptly close the connection (looks like ECONNRESET to the peer)
  kIoError,    // return an I/O error from the current operation
  kCorrupt,    // flip bytes in the next payload -- exercises the frame CRCs
  kKillSelf,   // _exit(137) without cleanup: the kill -9 case, from the inside
  kStall,      // sleep, to open a window for a concurrent operation
};

inline const char* to_string(FaultKind k) {
  switch (k) {
    case FaultKind::kNone: return "none";
    case FaultKind::kDropLink: return "drop_link";
    case FaultKind::kIoError: return "io_error";
    case FaultKind::kCorrupt: return "corrupt";
    case FaultKind::kKillSelf: return "kill_self";
    case FaultKind::kStall: return "stall";
  }
  return "?";
}

class FaultPlan {
 public:
  // Arm `point` to fire `kind` after `skip` prior visits (so a fault can be aimed at the
  // middle of a long phase rather than only its first instant). fires_max limits how many
  // times it triggers -- 1 by default, because a fault that re-fires on every retry turns
  // "recovers cleanly" into an infinite loop rather than a test.
  void arm(FaultPoint point, FaultKind kind, uint64_t skip = 0, uint64_t fires_max = 1) {
    const size_t i = static_cast<size_t>(point);
    if (i >= kFaultPointCount) return;
    std::lock_guard<std::mutex> g(mu_);
    entries_[i] = Entry{kind, skip, fires_max, 0, 0};
    armed_.fetch_or(bit(i), std::memory_order_release);
  }

  void clear() {
    std::lock_guard<std::mutex> g(mu_);
    for (auto& e : entries_) e = Entry{};
    armed_.store(0, std::memory_order_release);
  }

  // The hot-path check. One relaxed load and a predictable branch when nothing is armed,
  // which is always the case in production.
  FaultKind check(FaultPoint point) {
    const size_t i = static_cast<size_t>(point);
    if (i >= kFaultPointCount) return FaultKind::kNone;
    if ((armed_.load(std::memory_order_acquire) & bit(i)) == 0) return FaultKind::kNone;
    std::lock_guard<std::mutex> g(mu_);
    Entry& e = entries_[i];
    if (e.kind == FaultKind::kNone) return FaultKind::kNone;
    if (e.visits++ < e.skip) return FaultKind::kNone;
    if (e.fired >= e.fires_max) return FaultKind::kNone;
    e.fired++;
    return e.kind;
  }

  uint64_t fire_count(FaultPoint point) const {
    const size_t i = static_cast<size_t>(point);
    if (i >= kFaultPointCount) return 0;
    std::lock_guard<std::mutex> g(mu_);
    return entries_[i].fired;
  }

  bool any_armed() const { return armed_.load(std::memory_order_acquire) != 0; }

 private:
  struct Entry {
    FaultKind kind = FaultKind::kNone;
    uint64_t skip = 0;
    uint64_t fires_max = 1;
    uint64_t visits = 0;
    uint64_t fired = 0;
  };
  static constexpr uint64_t bit(size_t i) { return uint64_t{1} << i; }

  std::atomic<uint64_t> armed_{0};
  mutable std::mutex mu_;
  std::array<Entry, kFaultPointCount> entries_{};
};

static_assert(kFaultPointCount <= 64, "armed_ is a 64-bit mask");

inline FaultPlan& global_faults() {
  static FaultPlan p;
  return p;
}

// Sugar for the production call sites, so an injection point reads as one line.
#define WANREP_FAULT(point) ::wanrep::global_faults().check(point)

}  // namespace wanrep
