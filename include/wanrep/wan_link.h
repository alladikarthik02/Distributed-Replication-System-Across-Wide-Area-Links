// Emulated wide-area conditions on top of any other Link: fixed latency, a bandwidth
// ceiling, and reproducible jitter (SPEC 3.8).
//
// WHY EMULATE AT ALL:
//   Every headline claim in this project is about a HIGH-LATENCY link (SPEC R1.6, 3.2),
//   and a real wide-area path is not reproducible: its RTT, its cross traffic and its
//   loss all change between two runs, so a benchmark taken across one measures the
//   internet rather than this code. A test that depends on the internet is not a test.
//   `tc netem` in the container gives a real-kernel cross-check of the latency path; it
//   is not a replacement, because it cannot be part of a deterministic fault matrix.
//
// THE HALF-RTT MODEL, AND WHY THE DELAY LIVES ON THE READ SIDE:
//   Each WanLink applies rtt/2 as a ONE-WAY delivery delay, so a request through one and
//   a response through its peer costs one full RTT -- which is what "RTT" means to the
//   protocol designer reading SPEC 3.2's round-trips-per-GiB number. The delay is applied
//   where bytes are RECEIVED: a byte is stamped with the instant it was pulled off the
//   inner link and withheld from the caller until stamp + rtt/2. Delaying on the write
//   side instead would have been wrong in a way that matters -- it would stall the
//   SENDER, so a pipelined sender streaming frames (SPEC 3.2 sends payload without
//   per-chunk acknowledgement) would be throttled to one frame per RTT and the emulator
//   would manufacture exactly the pathology the protocol was designed to avoid.
//
// WHY A TOKEN BUCKET FOR BANDWIDTH:
//   A bucket separates the average rate from the burst size, which is the only honest
//   two-parameter model of a shaped link. The bucket starts EMPTY on purpose: a full
//   bucket would hand the first N bytes across for free, and over the short transfers a
//   fast test suite can afford, that free burst would show up as a measured throughput
//   above the configured ceiling. Idle credit on a real path is bufferbloat, which is on
//   the list of things below that this does not model.
//
// WHAT THIS IS NOT (SPEC 8.8) -- stated here because an emulator whose limits are not
// written down gets quoted as if it were a WAN:
//   * NO packet loss and NO reordering. Both live BELOW TCP. Injecting them above it
//     would be theatre: the bytes handed to us have already been retransmitted and
//     re-ordered into place by the kernel, so "dropping" one here does not exercise any
//     recovery path that exists -- it just corrupts a stream that TCP guarantees. Real
//     loss changes throughput through congestion control, and that is the effect we
//     cannot reproduce this way, so we do not pretend to.
//   * NO congestion-control dynamics: no slow start, no cwnd collapse on loss, no
//     competing flows, no bufferbloat, no MTU discovery, no tail latency of a real path.
//   * The FLOOR. T0 measured loopback RTT at p50 2.6-10.2 us with p99 excursions to
//     54 us (SPEC 2.5). Add the scheduler's wake-up granularity on sleep_until (order
//     0.1 ms) and the noise floor is a few hundred microseconds. An emulated RTT below
//     ~1 ms would therefore be mostly measuring the host, which is why SPEC 3.8's curve
//     starts at 10 ms and the 0 ms point is labelled "loopback", not "0 ms WAN".
//
// DETERMINISM (SPEC S15): jitter is drawn from a seeded splitmix64, never from the wall
//   clock, so an emulated run replays identically given the seed. `bandwidth_mbps` and
//   `rtt_ms` are exact; only the jitter is random, and only from that stream.
#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "wanrep/link.h"
#include "wanrep/result.h"

namespace wanrep {

namespace wan_detail {

using Clock = std::chrono::steady_clock;  // T0: is_steady, ~41 ns granularity (SPEC 2.5)
using TimePoint = Clock::time_point;

inline uint64_t splitmix64(uint64_t& state) {
  uint64_t z = (state += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

// Uniform in [0, jitter_ms]. ADDITIVE only, never subtractive: jitter on a real path is
// queueing delay, and a queue can make a packet late but never early. A symmetric model
// would let the emulator deliver bytes sooner than the configured RTT, which would make
// "measured >= configured" -- the one assertion that proves the delay was applied at all
// -- untestable.
//
// Free function rather than a private method so the determinism itself is directly
// testable: two identical states must produce identical sequences (SPEC S15).
inline double jitter_draw_ms(uint64_t& state, double jitter_ms) {
  if (jitter_ms <= 0.0) return 0.0;
  // Top 53 bits -> [0,1) exactly, the standard construction; the low bits of a
  // splitmix64 output are as good as the high ones, but taking the top 53 keeps the
  // mapping to double exact and free of rounding to 1.0.
  const double u = static_cast<double>(splitmix64(state) >> 11) * (1.0 / 9007199254740992.0);
  return u * jitter_ms;
}

// Milliseconds (a double, ultimately from a human typing `--rtt`) to a steady_clock
// duration, saturating rather than overflowing.
//
// THE CLAMP IS NOT DEFENSIVE DECORATION -- UBSan caught this. Converting a double outside
// int64's range to an integer duration is UNDEFINED behaviour, and on this project's
// aarch64 target it does not produce garbage but INT64_MAX, which is worse: the very next
// `now + d` in sleep_until is then a signed-integer overflow ("3142920371930 +
// 9223372036854775807 cannot be represented in type 'long int'"). What the caller gets
// back is a deadline with no relationship to the request -- either in the past, so the
// emulator silently applies no delay while claiming to, or absurdly far ahead, so the
// process parks and the layer above cannot tell that from a deadlock.
//
// The ceiling is 1e17 ns (~3.2 years): finite, still meaninglessly large as a delay, and
// two orders of magnitude below int64's 9.2e18 ns so that `now + d` has room as well.
// `!(ms > 0.0)` rather than `ms <= 0.0` so that a NaN takes the zero branch instead of
// reaching the conversion, where it would be undefined too.
inline Clock::duration ms_to_duration(double ms) {
  if (!(ms > 0.0)) return Clock::duration::zero();
  constexpr double kMaxNs = 1e17;
  const double ns = std::min(ms * 1e6, kMaxNs);
  return std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double, std::nano>(ns));
}

}  // namespace wan_detail

class WanLink : public Link {
 public:
  // Every field's 0 means "this dimension is disabled", so a default-constructed Params
  // makes WanLink a transparent pass-through. That matters for the benchmarks: the
  // loopback row of SPEC R1.6's RTT curve must go through the SAME code path as the
  // 200 ms row, or the curve compares two different programs.
  struct Params {
    double rtt_ms = 0;          // full round trip; half is applied per direction
    double bandwidth_mbps = 0;  // megaBITS per second, as links are sold
    double jitter_ms = 0;       // uniform [0, jitter_ms], added to the one-way delay
    uint64_t seed = 0;          // 0 is a valid seed; jitter is disabled by jitter_ms == 0
  };

  // ---- Parameter bounds, and what decided each number ----------------------
  //
  // These values are not wire data, so this is not SPEC S12 -- they come from `--rtt` and
  // `--bw` on SPEC 4.2's command line, which is to say from a human, which is to say
  // eventually from a typo. They are bounded for an arithmetic reason rather than a
  // stylistic one: every one of them becomes a duration (see ms_to_duration above, where
  // UBSan found the overflow), and an out-of-range value produces either a silent absence
  // of the emulation the caller asked for or a park so long the layer above cannot
  // distinguish it from a deadlock. A run that quietly emulated something other than what
  // was configured would put a wrong number in BENCHMARKS.md with nothing to notice it, so
  // out-of-range parameters are clamped AND reported through params_were_clamped().
  static constexpr double kMaxRttMs = 60000.0;        // one minute. Geostationary satellite
                                                      // is ~600 ms and SPEC 3.8's curve
                                                      // stops at 200 ms; past this is not a
                                                      // network path, it is a typo.
  static constexpr double kMinBandwidthMbps = 0.001;  // 1 Kbit/s -- slower than a 1200-baud
                                                      // modem. Below it even a single byte
                                                      // takes longer than any test or human
                                                      // will wait, which is how a mistyped
                                                      // flag became an apparent hang.
  static constexpr double kMaxBandwidthMbps = 1e6;    // 1 Tbit/s: above any link that
                                                      // exists, and it keeps rate x burst
                                                      // far inside double's exact range.

  // True if `p` asks for something outside those bounds (NaN counts: a NaN comparison is
  // false either way, so it is caught by asking whether the value is IN range, never
  // whether it is out).
  static bool params_out_of_range(const Params& p) {
    const bool rtt_ok = (p.rtt_ms >= 0.0 && p.rtt_ms <= kMaxRttMs);
    const bool jitter_ok = (p.jitter_ms >= 0.0 && p.jitter_ms <= kMaxRttMs);
    const bool bw_ok = (p.bandwidth_mbps == 0.0) ||
                       (p.bandwidth_mbps >= kMinBandwidthMbps &&
                        p.bandwidth_mbps <= kMaxBandwidthMbps);
    return !(rtt_ok && jitter_ok && bw_ok);
  }

  // The effective parameters: what this link will actually emulate.
  static Params clamped_params(Params p) {
    p.rtt_ms = clamp_or_zero(p.rtt_ms, 0.0, kMaxRttMs);
    p.jitter_ms = clamp_or_zero(p.jitter_ms, 0.0, kMaxRttMs);
    if (!(p.bandwidth_mbps > 0.0)) {
      p.bandwidth_mbps = 0.0;  // <= 0 or NaN: the dimension is simply disabled
    } else {
      p.bandwidth_mbps = std::min(std::max(p.bandwidth_mbps, kMinBandwidthMbps),
                                  kMaxBandwidthMbps);
    }
    return p;
  }

  // The checked way to build one, for call sites that have a caller to complain to --
  // SPEC 4.2's `--rtt` / `--bw` flags above all. The constructor cannot refuse (it has no
  // way to return an error), so it clamps; this returns kInvalidArgument instead, which is
  // what a human who mistyped a flag actually wants: a message at startup rather than a
  // benchmark that ran an hour and measured a different link.
  static Result<std::shared_ptr<WanLink>> create(std::shared_ptr<Link> inner, Params p) {
    if (params_out_of_range(p)) {
      return err(Err::kInvalidArgument,
                 "WanLink parameters out of range (rtt_ms 0.." + std::to_string(kMaxRttMs) +
                     ", bandwidth_mbps 0 or " + std::to_string(kMinBandwidthMbps) + ".." +
                     std::to_string(kMaxBandwidthMbps) + ")");
    }
    return std::make_shared<WanLink>(std::move(inner), p);
  }

  WanLink(std::shared_ptr<Link> inner, Params raw)
      : inner_(std::move(inner)),
        clamped_(params_out_of_range(raw)),
        p_(clamped_params(raw)),
        rng_(p_.seed),
        one_way_(wan_detail::ms_to_duration(p_.rtt_ms / 2.0)),
        pipelined_window_(std::min(one_way_ / 4, wan_detail::ms_to_duration(kPipelineWindowMs))),
        rate_bytes_per_s_(p_.bandwidth_mbps > 0 ? p_.bandwidth_mbps * 1e6 / 8.0 : 0.0),
        capacity_bytes_(rate_bytes_per_s_ > 0
                            ? std::max(kMinBurstBytes, rate_bytes_per_s_ * kBurstSeconds)
                            : 0.0),
        last_refill_(wan_detail::Clock::now()) {}

  // Paced by the token bucket, then handed to the inner link. The return value is what
  // the INNER link accepted, short writes included -- the emulator must not paper over
  // the short-write behaviour T0 measured (SPEC 2.5), because write_all()'s correctness
  // against it is exactly what the benchmarks run through.
  Result<size_t> write_some(const uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    std::lock_guard<std::mutex> g(tx_mu_);
    size_t want = n;
    if (rate_bytes_per_s_ > 0.0) {
      // Cap the slice so pacing is smooth rather than a single long sleep: a 1 MiB write
      // at 20 Mbit/s would otherwise park the sender for 400 ms and deliver in one lump,
      // which is not what a shaped link looks like to the receiver. 16 KiB is ~6.5 ms at
      // 20 Mbit/s -- fine-grained next to the RTTs we emulate, and coarse enough that the
      // ~0.1 ms sleep overshoot is under 2% of each slice.
      want = std::min(n, kTxSliceBytes);
      spend_tokens(static_cast<double>(want));
    }
    auto r = inner_->write_some(p, want);
    if (r.ok() && rate_bytes_per_s_ > 0.0) {
      // Refund what the inner link did not take. Without this the bucket would charge for
      // bytes that never crossed, and a link whose peer is slow would appear slower than
      // its configured ceiling for a reason that has nothing to do with the ceiling.
      refund_tokens(static_cast<double>(want - *r));
    }
    return r;
  }

  // The delay lives here (see the file header). Bytes are pulled from the inner link in
  // slices, stamped with the instant they arrived, and withheld until stamp + rtt/2.
  //
  // A DELAY LINE MUST NOT BECOME A THROUGHPUT CEILING -- the read side's version of the
  // mistake the write side was designed to avoid, and it was in here until an adversarial
  // test measured it. The naive rule "every slice is withheld for rtt/2" serializes a bulk
  // stream to one slice per half-RTT, so the emulated link tops out at
  // kRxSliceBytes/(rtt/2): measured 18.9 Mbit/s at a 50 ms RTT over a loopback path that
  // does 13 Gbit/s, and worse in inverse proportion as the RTT grows. bench/rtt_curve
  // (SPEC R1.6) would then have been plotting the emulator's own ceiling and calling it
  // the protocol's shape -- an instrument manufacturing the very pathology SPEC 3.2 warns
  // about. A fixed one-way delay costs a stream its FIRST byte and nothing after that.
  //
  // The fix needs one bit of information the emulator cannot get from the byte count
  // alone: did these bytes arrive just now, or were they already sitting in the inner
  // link's receive buffer because they crossed while the previous slice was being
  // withheld? Bytes in the second case have already served their flight time -- charging
  // them another is what builds the ceiling. TWO measured facts decide it, and it takes
  // both:
  //   1. the pull came back essentially instantly, so the data was already queued rather
  //      than arriving while we waited for it, AND
  //   2. we came back for it essentially the moment the caller finished the previous
  //      slice, so this is one continuous stream and not a fresh burst.
  // "Essentially" is one quarter of the one-way delay, capped at 1 ms: enormous next to a
  // buffered loopback recv (single-digit microseconds, SPEC 2.5) and tiny next to any RTT
  // this emulator is meant to model (SPEC 3.8 starts its curve at 10 ms, i.e. a 5 ms
  // one-way). Misjudging in the conservative direction costs one slice one extra delay; it
  // cannot reintroduce the ceiling, because the ceiling came from charging EVERY slice.
  //
  // CONDITION 2 IS NOT REDUNDANT, and leaving it out was a real regression caught by
  // running the suite on a deliberately loaded container: with only condition 1, a reader
  // thread that is DESCHEDULED between two reads comes back to find the peer's bytes
  // already waiting, the pull returns instantly, and a byte that should have been held for
  // a full one-way delay is handed over immediately. The existing jitter test -- whose
  // whole content is that no sample ever lands below the configured RTT -- failed 2 runs
  // in 6 under load. Condition 2 rejects exactly that case, because the gap between
  // finishing the last slice and asking for the next one is where the deschedule shows up.
  // The comparison is against the moment the previous slice was DRAINED, never against
  // its delivery deadline: sleep_until overshoots that deadline by ~1 ms in this container
  // (see test_link.cpp's RTT budget), so comparing against the deadline would mostly be
  // measuring our own sleep, which is how an earlier attempt put the ceiling back.
  //
  // The first pull of a connection always pays in full, tracked by an explicit flag:
  // nothing was in flight before the link existed, and that first delay is what makes a
  // request/response round trip measure the configured RTT.
  //
  // The limitation this leaves, stated rather than hidden: bytes that arrive while nobody
  // is calling read_some sit in the kernel's buffer un-timed, and are delivered without
  // the delay when the caller finally asks. The emulator can only delay bytes it is
  // watching. That errs toward the model already declared here -- no bufferbloat, no queue
  // that adds delay of its own -- and it never delays a stream that a real path would not.
  //
  // Consequence worth naming: a slice already pulled from the inner link is delivered to
  // the caller even if the connection is dropped a microsecond later, because those bytes
  // are modelled as already in flight. That is the physically honest behaviour -- bytes
  // on the wire when the far end dies still arrive -- and it is why FaultLink's drop
  // point is defined in terms of bytes handed to the transport (SPEC 3.8).
  Result<size_t> read_some(uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    std::lock_guard<std::mutex> g(rx_mu_);
    if (rx_pos_ >= rx_len_) {
      if (rx_buf_.size() < kRxSliceBytes) rx_buf_.resize(kRxSliceBytes);
      const auto asked = wan_detail::Clock::now();
      auto r = inner_->read_some(rx_buf_.data(), rx_buf_.size());
      if (!r.ok()) return r.error();  // an error is delivered immediately; see below
      const auto arrived = wan_detail::Clock::now();
      // The count came from another Link, and it is about to bound a memcpy out of a heap
      // buffer. A transport that over-reported would make `rx_len_ - rx_pos_` a size that
      // walks off the end of rx_buf_ -- a heap over-read handed straight to the caller.
      // Validating a length before using it to bound a copy is the same rule SPEC S7
      // applies to the wire, and it costs one comparison per slice.
      if (*r > rx_buf_.size()) {
        return err(Err::kIo, "inner link reported more bytes than it was asked for");
      }
      rx_len_ = *r;
      rx_pos_ = 0;
      const bool already_in_flight = pulled_once_ &&
                                     (arrived - asked) <= pipelined_window_ &&
                                     (asked - drained_at_) <= pipelined_window_;
      pulled_once_ = true;
      if (already_in_flight) {
        // These bytes crossed the emulated path while the previous slice was being held
        // back, so their flight time is already spent. std::max keeps the delivery clock
        // monotonic rather than letting a slice overtake the one before it.
        rx_ready_ = std::max(rx_ready_, arrived);
      } else {
        // A genuinely new arrival: the full one-way delay, plus a jitter draw. The draw is
        // consumed only on this branch, so the random stream advances once per DELAYED
        // slice and a run still replays exactly from its seed (SPEC S15).
        rx_ready_ = arrived + one_way_ +
                    wan_detail::ms_to_duration(wan_detail::jitter_draw_ms(rng_, p_.jitter_ms));
      }
    }
    // Errors (kClosed/kReset) are NOT delayed. A FIN or an RST is a link-state change,
    // not a payload byte, and holding one for rtt/2 would only delay the moment a test
    // observes a failure it has already caused -- it would not make the emulation more
    // faithful, because the ordering against the delayed bytes is unchanged.
    std::this_thread::sleep_until(rx_ready_);
    const size_t k = std::min(n, rx_len_ - rx_pos_);
    std::memcpy(p, rx_buf_.data() + rx_pos_, k);
    rx_pos_ += k;
    // The instant the caller ran out of delivered bytes. The NEXT pull is compared against
    // this, not against rx_ready_ -- see condition 2 above.
    if (rx_pos_ >= rx_len_) drained_at_ = wan_detail::Clock::now();
    return k;
  }

  void close() override { inner_->close(); }
  bool is_open() const override { return inner_->is_open(); }

  // Delegated, never counted here. SPEC 4.1 makes bytes_out the authoritative wire-byte
  // counter for every bandwidth claim in the project, so it must report what actually
  // crossed the transport -- the emulator is a lens on the wire, not a second wire.
  uint64_t bytes_out() const override { return inner_->bytes_out(); }
  uint64_t bytes_in() const override { return inner_->bytes_in(); }

  std::string describe() const override {
    char buf[96];
    std::snprintf(buf, sizeof(buf), "wan[rtt=%.1fms bw=%.1fMbps jitter=%.1fms]/", p_.rtt_ms,
                  p_.bandwidth_mbps, p_.jitter_ms);
    return std::string(buf) + inner_->describe();
  }

  // The EFFECTIVE parameters -- what is being emulated, which is what a benchmark header
  // must print. If they differ from what the caller asked for, params_were_clamped() says
  // so; silently emulating something other than the configuration is how a wrong number
  // gets into BENCHMARKS.md with nothing to catch it.
  const Params& params() const { return p_; }
  bool params_were_clamped() const { return clamped_; }
  const std::shared_ptr<Link>& inner() const { return inner_; }

 private:
  // Clamps into [lo, hi]; a NaN (which compares false against everything) becomes `lo`.
  static double clamp_or_zero(double v, double lo, double hi) {
    if (!(v > lo)) return lo;
    return std::min(v, hi);
  }

  // 20 ms of credit, floored at one MTU. Small enough that a short benchmark is not
  // distorted by the burst, large enough to absorb one scheduler wake-up's worth of
  // overshoot so the average rate converges on the configured one instead of drifting
  // low by the sleep granularity.
  static constexpr double kBurstSeconds = 0.02;
  static constexpr double kMinBurstBytes = 1500.0;
  static constexpr size_t kTxSliceBytes = 16u * 1024;
  static constexpr size_t kRxSliceBytes = 64u * 1024;
  // The ceiling on "essentially instantly" in read_some. One quarter of the one-way delay
  // is the scale-free part; this caps it so that a very large emulated RTT does not widen
  // the window to the point where a real idle gap looks like a pipelined stream.
  static constexpr double kPipelineWindowMs = 1.0;

  void refill_locked(wan_detail::TimePoint now) {
    const double dt = std::chrono::duration<double>(now - last_refill_).count();
    last_refill_ = now;
    if (dt > 0.0) {
      tokens_ = std::min(capacity_bytes_, tokens_ + dt * rate_bytes_per_s_);
    }
  }

  void spend_tokens(double bytes) {
    auto now = wan_detail::Clock::now();
    refill_locked(now);
    if (tokens_ >= bytes) {
      tokens_ -= bytes;
      return;
    }
    // Sleep for exactly the shortfall. Note the bucket is allowed to run to zero rather
    // than being clamped at the burst capacity here: capacity bounds accumulated IDLE
    // credit, not the size of a single paced write.
    const double deficit = bytes - tokens_;
    std::this_thread::sleep_until(now + wan_detail::ms_to_duration(deficit / rate_bytes_per_s_ * 1e3));
    refill_locked(wan_detail::Clock::now());
    tokens_ = std::max(0.0, tokens_ - bytes);
  }

  void refund_tokens(double bytes) {
    if (bytes <= 0.0) return;
    tokens_ = std::min(capacity_bytes_, tokens_ + bytes);
  }

  std::shared_ptr<Link> inner_;
  bool clamped_;  // declared before p_: the constructor reads the raw params for this
                  // flag and then stores the clamped ones, in that order
  Params p_;
  uint64_t rng_;
  wan_detail::Clock::duration one_way_;
  wan_detail::Clock::duration pipelined_window_;

  // Write side (token bucket).
  mutable std::mutex tx_mu_;
  double rate_bytes_per_s_ = 0.0;
  double capacity_bytes_ = 0.0;
  double tokens_ = 0.0;  // starts empty -- see the file header
  wan_detail::TimePoint last_refill_;

  // Read side (delay line). One slice in flight at a time, which is enough: the model is
  // a fixed delay, so a second slice pulled later is simply stamped later.
  mutable std::mutex rx_mu_;
  std::vector<uint8_t> rx_buf_;
  size_t rx_len_ = 0;
  size_t rx_pos_ = 0;
  bool pulled_once_ = false;  // the first slice on a link was never "already in flight"
  wan_detail::TimePoint drained_at_{};  // when the caller consumed the last delivered byte
  wan_detail::TimePoint rx_ready_{};
};

}  // namespace wanrep
