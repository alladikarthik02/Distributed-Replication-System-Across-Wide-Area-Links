// T5: the link layer -- a real socket, an emulated WAN, and injected failures.
//
// The tests that matter most here are the ones that assert a CODE rather than a
// condition:
//
//   * tcp_orderly_close_reads_as_closed / tcp_abortive_close_reads_as_reset. T0 measured
//     that a FIN reads as 0 and an RST reads as ECONNRESET (SPEC 2.5); SPEC 3.7's resume
//     logic branches on exactly that difference, and if the two ever collapsed into one
//     generic "io error" the system would commit a TRUNCATED transfer as complete (S5).
//     "An error happened" is therefore not an acceptable assertion in either test -- the
//     specific code is the requirement.
//
//   * tcp_write_to_a_dead_peer_is_an_errno_not_a_dead_process. The assertion is partly
//     that the test reaches its last line at all: without MSG_NOSIGNAL the process is
//     killed by signal 13 here, which T0 proved by forking a child that did exactly that.
//
//   * wan_link_measured_rtt_tracks_its_configuration prints its numbers. An emulator
//     nobody measured is a constant multiplied by hope, and every latency claim in SPEC
//     R1.6 is taken through this code.
//
// THE SECOND HALF OF THIS FILE IS AN ADVERSARIAL PASS over the same three classes, and
// four of its tests exist because they failed first:
//   * wan_link_latency_does_not_become_a_throughput_ceiling -- the delay line used to
//     serialise a stream to one 64 KiB slice per half-RTT, which capped an emulated
//     50 ms link at 18.9 Mbit/s over a loopback path that does 13 Gbit/s. SPEC R1.6's
//     whole curve is taken through this code.
//   * fault_link_corrupt_still_lands_when_the_write_comes_back_short -- an injected
//     corruption used to vanish whenever the transport short-wrote, which SPEC 2.5 says
//     is the normal case. The fault fired, fire_count() said 1, and the wire stayed clean.
//   * wan_link_absurd_parameters_do_not_become_undefined_behaviour / ms_to_duration -- a
//     mistyped --rtt or --bw reached a double -> nanoseconds conversion that UBSan calls
//     an overflow, and one of them parked the process indefinitely.
//   * links_reject_an_inner_link_that_over_reports_its_transfer -- a byte count from a
//     lower layer indexed a buffer unchecked; ASan calls the result a heap-buffer-overflow.
//   * tcp_link_counters_are_safe_to_read_while_the_link_is_busy -- SPEC 4.1's
//     authoritative counter was a plain uint64_t read from another thread; TSan calls that
//     a data race, and it was.
//
// TOLERANCES ARE DELIBERATELY LOOSE. This suite is run 25 times in a row to prove it does
// not flake (SPEC 2.5's last row), and a fault-injection project whose baseline suite
// flakes cannot tell an injected failure from a bad test. So every timing assertion here
// is a bound with an argued budget, never a tight equality, and wherever an ordering or a
// code can carry the meaning instead, it does.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "test.h"
#include "wanrep/crc32c.h"
#include "wanrep/fault_link.h"
#include "wanrep/link.h"
#include "wanrep/result.h"
#include "wanrep/tcp_link.h"
#include "wanrep/types.h"
#include "wanrep/wan_link.h"

using namespace wanrep;

namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

// Deterministic PRNG, same splitmix64 the rest of the project uses. Seeded from
// testing::seed() everywhere so a failure replays with WANREP_SEED (SPEC S15).
struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed) {}
  uint64_t next() {
    uint64_t z = (s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }
  void fill(std::vector<uint8_t>& v) {
    for (size_t i = 0; i < v.size(); i++) v[i] = static_cast<uint8_t>(next() >> 24);
  }
};

// Names the code in a failure message. CHECK_EQ on a raw `Err` would print
// "<unprintable>" (an enum class has no operator<<), and "got: reset vs closed" is the
// entire content of these assertions.
std::string code_name(Err e) { return to_string(e); }
std::string code_name(const Error& e) { return to_string(e.code); }

// Every socket in this suite carries a timeout. It is NOT part of what is being tested:
// it is a backstop so that a regression shows up as a red line in 20 seconds instead of a
// hung CI job, which matters more than usual here because several tests park a thread in
// a blocking read waiting for a failure to arrive.
TcpLink::Options opts() {
  TcpLink::Options o;
  o.timeout_ms = 20000;
  return o;
}

// Counts how many times write_all/read_exact actually had to go round their loops. This
// is the only way to turn "the short-transfer path is exercised" from a claim into a
// number, and the number is printed rather than merely asserted.
class CountingLink : public Link {
 public:
  explicit CountingLink(std::shared_ptr<Link> inner) : inner_(std::move(inner)) {}

  Result<size_t> write_some(const uint8_t* p, size_t n) override {
    auto r = inner_->write_some(p, n);
    if (r.ok()) {
      writes++;
      largest_write = std::max(largest_write, *r);
    }
    return r;
  }
  Result<size_t> read_some(uint8_t* p, size_t n) override {
    auto r = inner_->read_some(p, n);
    if (r.ok()) {
      reads++;
      largest_read = std::max(largest_read, *r);
      smallest_read = std::min(smallest_read, *r);
    }
    return r;
  }
  void close() override { inner_->close(); }
  bool is_open() const override { return inner_->is_open(); }
  uint64_t bytes_out() const override { return inner_->bytes_out(); }
  uint64_t bytes_in() const override { return inner_->bytes_in(); }
  std::string describe() const override { return "counting/" + inner_->describe(); }

  size_t writes = 0, reads = 0;
  size_t largest_write = 0, largest_read = 0;
  size_t smallest_read = static_cast<size_t>(-1);

 private:
  std::shared_ptr<Link> inner_;
};

struct Pair {
  std::shared_ptr<TcpLink> client;
  std::shared_ptr<TcpLink> server;
};

// A connected loopback pair on a kernel-chosen port. No thread: a blocking connect()
// completes as soon as the kernel puts the connection on the listen backlog, so accept()
// can happen afterwards on the same thread. (The threaded form is exercised explicitly in
// tcp_round_trip_through_write_all_and_read_exact, since that is how a server really
// runs.)
Pair connected_pair(const TcpLink::Options& o) {
  auto lst = TcpLink::Listener::bind("127.0.0.1", 0, o);
  if (!lst.ok()) {
    std::printf("    setup: bind failed: %s\n", lst.error().message().c_str());
    return {};
  }
  auto cli = TcpLink::connect("127.0.0.1", lst->port(), o);
  if (!cli.ok()) {
    std::printf("    setup: connect failed: %s\n", cli.error().message().c_str());
    return {};
  }
  auto srv = lst->accept();
  if (!srv.ok()) {
    std::printf("    setup: accept failed: %s\n", srv.error().message().c_str());
    return {};
  }
  return Pair{*cli, *srv};
}

}  // namespace

// ---------------------------------------------------------------------------
// TcpLink: the real socket
// ---------------------------------------------------------------------------

TEST(tcp_round_trip_through_write_all_and_read_exact) {
  auto lst = TcpLink::Listener::bind("127.0.0.1", 0, opts());
  REQUIRE(lst.ok());

  // Port 0 asked for an ephemeral port; the listener must report the real one. A test
  // that hard-coded a port would fail whenever a previous run's socket is in TIME_WAIT
  // or another agent is building the same repo -- a flake with an external cause.
  const uint16_t port = lst->port();
  CHECK_GT(port, uint16_t{0});

  std::shared_ptr<TcpLink> server;
  std::thread acceptor([&] {
    auto s = lst->accept();
    if (s.ok()) server = *s;
  });
  auto cli = TcpLink::connect("127.0.0.1", port, opts());
  acceptor.join();
  REQUIRE(cli.ok());
  REQUIRE(server != nullptr);
  auto client = *cli;

  constexpr size_t kN = 64u * 1024;  // larger than a default loopback socket buffer slice
  std::vector<uint8_t> payload(kN);
  Rng rng(testing::seed());
  rng.fill(payload);

  // The echo runs in a thread because 64 KiB does not fit in the socket buffers: a
  // single-threaded write_all of that size would deadlock against a peer that is not
  // reading, which is itself worth knowing about the transport.
  std::atomic<bool> echo_ok{false};
  std::thread echo([&] {
    std::vector<uint8_t> buf(kN);
    if (!read_exact(*server, buf.data(), buf.size()).ok()) return;
    if (!write_all(*server, buf.data(), buf.size()).ok()) return;
    echo_ok.store(true);
  });

  const bool sent = write_all(*client, payload.data(), payload.size()).ok();
  CHECK(sent);
  std::vector<uint8_t> back(kN, 0);
  const bool got = sent && read_exact(*client, back.data(), back.size()).ok();
  CHECK(got);
  if (!sent || !got) client->close();
  echo.join();

  CHECK(echo_ok.load());
  CHECK(back == payload);

  // The byte counters are not bookkeeping: SPEC 4.1 makes bytes_out the authoritative
  // wire-byte counter behind every bandwidth number this project reports, so it has to
  // agree with what was actually handed to the transport.
  CHECK_EQ(client->bytes_out(), uint64_t{kN});
  CHECK_EQ(client->bytes_in(), uint64_t{kN});
  CHECK_EQ(server->bytes_in(), uint64_t{kN});
  CHECK_EQ(server->bytes_out(), uint64_t{kN});
}

// A 4 MiB transfer through 16 KiB socket buffers -- the SPEC 2.5 short-transfer
// behaviour exercised for real rather than measured once.
//
// A CORRECTION TO WHAT T0 IMPLIED, found by running this: T0 forced its famous
// "one send() of 4 MiB moved 6 144 bytes" by putting the socket in O_NONBLOCK first.
// On a BLOCKING socket Linux's tcp_sendmsg waits for buffer space rather than returning
// early, so a single write_some of 4 MiB returns 4 MiB no matter how small SO_SNDBUF is;
// the short-WRITE path is reached through EINTR-after-partial-copy and SO_SNDTIMEO, not
// through buffer pressure. That does not weaken S11's rule at all -- it strengthens the
// reason for it, because the rule must not depend on which of those conditions a
// particular kernel and socket mode happen to produce. The short-READ path, by contrast,
// is unavoidable and constant, and this test counts both so the difference is a printed
// number instead of an assumption.
TEST(tcp_large_transfer_survives_small_socket_buffers) {
  TcpLink::Options o = opts();
  o.send_buffer_bytes = 16 * 1024;
  o.recv_buffer_bytes = 16 * 1024;
  auto p = connected_pair(o);
  REQUIRE(p.client && p.server);

  constexpr size_t kN = 4u << 20;  // 4 MiB: 128 times the receive buffer
  std::vector<uint8_t> payload(kN);
  Rng rng(testing::seed() ^ 0xABCDEFull);
  rng.fill(payload);
  const uint32_t want_crc = crc32c(ByteSpan(payload.data(), payload.size()));

  auto tx = std::make_shared<CountingLink>(p.client);
  auto rx = std::make_shared<CountingLink>(p.server);

  std::atomic<bool> rx_ok{false};
  std::atomic<uint32_t> rx_crc{0};
  std::thread reader([&] {
    std::vector<uint8_t> in(kN);
    if (!read_exact(*rx, in.data(), in.size()).ok()) return;
    rx_crc.store(crc32c(ByteSpan(in.data(), in.size())));
    rx_ok.store(true);
  });

  const bool ok = write_all(*tx, payload.data(), payload.size()).ok();
  CHECK(ok);
  if (!ok) tx->close();
  reader.join();

  std::printf("    note: %zu bytes through 16 KiB buffers: write_all took %zu write_some "
              "call(s) (largest %zu); read_exact took %zu read_some call(s) "
              "(largest %zu, smallest %zu)\n",
              kN, tx->writes, tx->largest_write, rx->reads, rx->largest_read,
              rx->smallest_read);

  CHECK(rx_ok.load());
  CHECK_EQ(rx_crc.load(), want_crc);  // every byte, in order, unmodified
  // The receiver genuinely had to loop: a read_exact that assumed one recv per structure
  // would have truncated this transfer more than a hundred times over.
  CHECK_GT(rx->reads, size_t{1});
  CHECK_LT(rx->largest_read, kN);
  CHECK_EQ(p.client->bytes_out(), uint64_t{kN});
  CHECK_EQ(p.server->bytes_in(), uint64_t{kN});
}

// The short-WRITE path on a real socket, produced deliberately rather than hoped for.
//
// The test above discovered that buffer pressure alone does NOT short a blocking send():
// Linux's tcp_sendmsg waits for space instead of returning early. So this one reproduces
// the condition that does -- a send timeout with bytes already copied -- because S11's
// rule ("write_all is the only way to touch a socket") is worth exactly as much as the
// evidence that write_some really can come back short. Without a case like this the
// codebase would contain a loop that is never taken on the transport that ships.
//
// Mechanism: SO_SNDTIMEO with nobody reading. The kernel copies whatever fits in the send
// buffer plus the peer's receive window, blocks, hits the timeout, and returns the partial
// count -- tcp_sendmsg's `return copied ? copied : err`. The buffers start EMPTY, so
// `copied` is guaranteed positive and the -1/EAGAIN branch is unreachable here; that is
// what makes this deterministic rather than a race dressed up as a test.
TEST(tcp_write_some_really_can_come_back_short) {
  TcpLink::Options o = opts();
  o.send_buffer_bytes = 16 * 1024;
  o.recv_buffer_bytes = 16 * 1024;
  o.timeout_ms = 250;  // the whole mechanism; long enough that a loaded container still
                       // finishes the initial copy, short enough to cost nothing
  auto p = connected_pair(o);
  REQUIRE(p.client && p.server);

  // Deliberately NO reader on p.server: the receive window must stay shut so the send
  // stalls after the first burst instead of streaming to completion.
  constexpr size_t kN = 4u << 20;
  std::vector<uint8_t> payload(kN, 0x6D);
  const auto r = p.client->write_some(payload.data(), payload.size());

  REQUIRE(r.ok());
  std::printf("    note: one write_some(%zu) on a stalled socket moved %zu bytes (%.4f%% "
              "of the request)\n",
              kN, *r, 100.0 * static_cast<double>(*r) / static_cast<double>(kN));
  CHECK_GT(*r, size_t{0});
  CHECK_LT(*r, kN);  // the point of the test: a positive return is not a complete one
  // write_some must never claim more than it was given -- a caller that trusted an
  // over-large count would advance its cursor past data it never sent, which is the
  // silent-truncation bug S11 exists to make impossible.
  CHECK_EQ(p.client->bytes_out(), static_cast<uint64_t>(*r));
}

// "The peer finished." SPEC 2.5.
TEST(tcp_orderly_close_reads_as_closed) {
  auto p = connected_pair(opts());
  REQUIRE(p.client && p.server);
  p.server->close();  // FIN

  uint8_t b = 0;
  auto r = p.client->read_some(&b, 1);
  CHECK(!r.ok());
  if (!r.ok()) CHECK_EQ(code_name(r.error()), code_name(Err::kClosed));
}

// "The peer DIED." SPEC 2.5, and the reason kClosed and kReset are separate enumerators:
// a resume that treated this case like the one above would accept a truncated transfer
// as a complete one (S5).
TEST(tcp_abortive_close_reads_as_reset) {
  auto p = connected_pair(opts());
  REQUIRE(p.client && p.server);
  p.server->close_abruptly();  // SO_LINGER {1,0} -> RST

  uint8_t b = 0;
  auto r = p.client->read_some(&b, 1);
  CHECK(!r.ok());
  if (!r.ok()) CHECK_EQ(code_name(r.error()), code_name(Err::kReset));
}

// Reaching the end of this test is itself the assertion: with the default SIGPIPE
// disposition the process is dead at the first failing write (T0: child died with
// signal 13). MSG_NOSIGNAL turns that into an errno we can resume from (SPEC 3.7).
TEST(tcp_write_to_a_dead_peer_is_an_errno_not_a_dead_process) {
  auto p = connected_pair(opts());
  REQUIRE(p.client && p.server);
  p.server->close_abruptly();

  // The first write may well succeed: TCP has nowhere to report the RST until it has been
  // processed, so the failure surfaces on a later call. The loop is bounded so a genuinely
  // broken mapping fails the test instead of spinning.
  Err code = Err::kOk;
  std::vector<uint8_t> buf(4096, 0xAB);
  int writes = 0;
  for (int i = 0; i < 1024; i++) {
    auto r = p.client->write_some(buf.data(), buf.size());
    if (!r.ok()) {
      code = r.error().code;
      break;
    }
    writes++;
  }
  std::printf("    note: %d writes accepted before the dead peer surfaced as '%s'\n", writes,
              code_name(code).c_str());
  CHECK_EQ(code_name(code), code_name(Err::kReset));
}

// ---------------------------------------------------------------------------
// WanLink: emulated latency and bandwidth
// ---------------------------------------------------------------------------

namespace {

constexpr int kRttIters = 12;

// The overhead budget the RTT assertions allow on top of the configured delay.
//
// Two sources, one of which is much larger than expected and was measured here rather
// than assumed:
//   * the transport floor -- T0 measured loopback RTT at p50 2.6-10.2 us with p99
//     excursions to 54 us (SPEC 2.5), and this test's 0 ms row re-measures it end to end
//     at ~0.04 ms including two thread hand-offs. Negligible.
//   * sleep_until overshoot -- ~1 ms per hop, so ~2 ms per round trip, in this container
//     (Docker on Apple silicon: the guest's timer granularity, not this code). That is an
//     order of magnitude worse than the ~0.1 ms a bare-metal Linux host would give, and it
//     is the term that actually sets this budget.
// 4.5 ms is a little over the ~4 ms this actually costs under ASan, and the assertion
// adds another 50% of the configured RTT on top for scheduling noise. It cannot simply be
// made enormous, and the ceiling is worth writing down: at the 10 ms row the budget has to
// stay UNDER 2x the configured RTT, or the most likely way to get this wrong -- applying
// the full RTT per hop instead of half -- would slip through. 10 + 4.5 + 5 = 19.5 < 20, so
// it still catches that. The tolerance is therefore the largest one that keeps the test
// meaningful, not the largest one that keeps it green.
//
// SPEC 3.8's note that emulated RTTs below ~1 ms would mostly measure the host is the same
// observation from the other side -- with this overshoot included, the honest floor for an
// emulated RTT in this container is nearer 5 ms than 1 ms.
constexpr double kOverheadMs = 4.5;

struct RttStats {
  double p50 = 0, lo = 0, hi = 0;
  bool ok = false;
};

// Round-trips a single byte through a pair of WanLinks. One byte because the point is
// latency, not throughput: the payload must be small enough that its transmission time is
// noise next to the emulated delay. TCP_NODELAY is what makes this honest -- with Nagle
// left on, a 1-byte round trip could pick up tens of milliseconds that have nothing to do
// with the emulator.
RttStats measure_rtt(double cfg_ms, double jitter_ms) {
  RttStats st;
  auto p = connected_pair(opts());
  if (!p.client || !p.server) return st;

  WanLink::Params par;
  par.rtt_ms = cfg_ms;
  par.jitter_ms = jitter_ms;
  par.seed = testing::seed();
  auto a = std::make_shared<WanLink>(p.client, par);
  auto b = std::make_shared<WanLink>(p.server, par);

  std::thread echo([&] {
    for (int i = 0; i < kRttIters; i++) {
      uint8_t byte = 0;
      if (!read_exact(*b, &byte, 1).ok()) return;
      if (!write_all(*b, &byte, 1).ok()) return;
    }
  });

  std::vector<double> samples;
  bool ok = true;
  for (int i = 0; i < kRttIters && ok; i++) {
    const uint8_t out = static_cast<uint8_t>(i);
    uint8_t in = 0;
    const auto t0 = Clock::now();
    ok = write_all(*a, &out, 1).ok() && read_exact(*a, &in, 1).ok();
    const double ms = ms_since(t0);
    if (ok && in == out) {
      samples.push_back(ms);
    } else {
      ok = false;
    }
  }
  if (!ok) a->close();  // release the echo thread rather than deadlocking the suite
  echo.join();
  if (!ok || samples.size() != static_cast<size_t>(kRttIters)) return st;

  std::sort(samples.begin(), samples.end());
  st.lo = samples.front();
  st.hi = samples.back();
  st.p50 = samples[samples.size() / 2];
  st.ok = true;
  return st;
}

}  // namespace

TEST(wan_link_measured_rtt_tracks_its_configuration) {
  const double cfgs[] = {0.0, 10.0, 50.0};
  double p50s[3] = {0, 0, 0};

  for (int i = 0; i < 3; i++) {
    const double cfg = cfgs[i];
    TCTX("configured_rtt_ms=" << cfg);
    const RttStats st = measure_rtt(cfg, /*jitter_ms=*/0.0);
    CHECK(st.ok);
    if (!st.ok) continue;
    p50s[i] = st.p50;
    std::printf("    note: configured %5.1f ms -> measured p50 %7.3f ms  min %7.3f  max %7.3f"
                "  (%d round trips)\n",
                cfg, st.p50, st.lo, st.hi, kRttIters);

    // Lower bound: the delay must actually have been applied. 0.95x rather than 1.0x only
    // to absorb the difference between two reads of the same clock, not to grant slack.
    CHECK_GE(st.p50, cfg * 0.95);
    // Upper bound: configured + the argued fixed overhead + 50% for scheduling on a
    // loaded container (see kOverheadMs). Generous, and still sharp enough to catch every
    // way this can actually break: an emulator that applied no delay, applied the FULL
    // RTT per hop instead of half, or applied it twice, misses this bound at every row.
    CHECK_LE(st.p50, cfg + kOverheadMs + cfg * 0.5);
  }

  // The ordering assertion is the one that cannot be satisfied by accident: a broken
  // emulator that ignored its parameter would still pass a generous absolute bound, but
  // it cannot produce a monotonically rising curve. SPEC R1.6's whole claim is about this
  // curve's shape.
  CHECK_LT(p50s[0], p50s[1]);
  CHECK_LT(p50s[1], p50s[2]);
  // And the 0 ms row is loopback, not "0 ms WAN" (SPEC 3.8): it must still be fast.
  CHECK_LT(p50s[0], kOverheadMs);
}

TEST(wan_link_jitter_only_ever_adds_delay) {
  const RttStats st = measure_rtt(/*cfg_ms=*/10.0, /*jitter_ms=*/5.0);
  REQUIRE(st.ok);
  std::printf("    note: rtt=10ms jitter=5ms -> min %7.3f  p50 %7.3f  max %7.3f ms\n", st.lo,
              st.p50, st.hi);
  // Jitter models queueing delay, which can make a byte late but never early. If the
  // minimum ever dipped below the configured RTT the model would be symmetric noise, and
  // the "measured >= configured" assertion above would stop meaning anything.
  CHECK_GE(st.lo, 10.0 * 0.95);
  // Two jitter draws per round trip (one per direction), each in [0, 5], so the model's
  // ceiling is 20 ms. The assertion is on the MEDIAN, not the maximum: a max is one
  // sample, so a bound on it is a bound on the single worst scheduling hiccup in the run
  // rather than on the emulator -- exactly the kind of assertion that passes 24 times and
  // fails the 25th. The maximum is still bounded, generously, because the emulator adding
  // unbounded delay would be a real defect worth catching.
  CHECK_LE(st.p50, 10.0 + 2 * 5.0 + kOverheadMs);
  CHECK_LE(st.hi, 10.0 + 2 * 5.0 + 4 * kOverheadMs);
}

TEST(wan_link_jitter_is_seeded_bounded_and_reproducible) {
  constexpr int kDraws = 1024;
  constexpr double kJitterMs = 5.0;
  uint64_t a = testing::seed();
  uint64_t b = testing::seed();
  double sum = 0;
  for (int i = 0; i < kDraws; i++) {
    TCTX("draw=" << i);
    const double x = wan_detail::jitter_draw_ms(a, kJitterMs);
    const double y = wan_detail::jitter_draw_ms(b, kJitterMs);
    CHECK_EQ(x, y);  // same seed, same stream -- SPEC S15
    CHECK_GE(x, 0.0);
    CHECK_LE(x, kJitterMs);
    sum += x;
  }
  const double mean = sum / kDraws;
  std::printf("    note: jitter mean over %d draws: %.4f ms (uniform [0,%.1f] expects %.2f)\n",
              kDraws, mean, kJitterMs, kJitterMs / 2);
  CHECK_GT(mean, kJitterMs * 0.4);
  CHECK_LT(mean, kJitterMs * 0.6);

  // A different seed must give a different stream, or "seeded" would be decoration.
  uint64_t c = testing::seed() ^ 0x1ull;
  uint64_t d = testing::seed();
  int differing = 0;
  for (int i = 0; i < 64; i++) {
    if (wan_detail::jitter_draw_ms(c, kJitterMs) != wan_detail::jitter_draw_ms(d, kJitterMs)) {
      differing++;
    }
  }
  CHECK_EQ(differing, 64);

  // jitter_ms == 0 disables it entirely and, importantly, consumes no randomness -- so a
  // run with jitter off is not merely quiet, it is the deterministic base case.
  uint64_t e = 12345;
  const uint64_t before = e;
  CHECK_EQ(wan_detail::jitter_draw_ms(e, 0.0), 0.0);
  CHECK_EQ(e, before);
}

namespace {

// Returns the effective throughput in Mbit/s, or -1 on failure.
//
// The clock stops when write_all returns, i.e. when the last byte has been handed to the
// transport -- not when it lands. For a shaped link that is the right boundary: the token
// bucket is what holds the sender back, and the receiver is drained concurrently so TCP
// backpressure is not what is being measured.
double transfer_mbps(double cap_mbps, size_t bytes) {
  auto p = connected_pair(opts());
  if (!p.client || !p.server) return -1;

  WanLink::Params par;
  par.bandwidth_mbps = cap_mbps;
  auto tx = std::make_shared<WanLink>(p.client, par);

  std::vector<uint8_t> payload(bytes, 0x5A);
  std::atomic<bool> rx_ok{false};
  std::thread rx([&] {
    std::vector<uint8_t> in(bytes);
    rx_ok.store(read_exact(*p.server, in.data(), in.size()).ok());
  });

  const auto t0 = Clock::now();
  const bool ok = write_all(*tx, payload.data(), payload.size()).ok();
  const double ms = ms_since(t0);
  if (!ok) tx->close();
  rx.join();
  if (!ok || !rx_ok.load() || ms <= 0) return -1;
  return static_cast<double>(bytes) * 8.0 / (ms / 1000.0) / 1e6;
}

}  // namespace

TEST(wan_link_bandwidth_cap_is_enforced) {
  constexpr double kMbps = 20.0;
  constexpr size_t kBytes = 1u << 20;  // 1 MiB -> ~0.42 s at 20 Mbit/s: long enough to
                                       // average over the 16 KiB pacing slices, short
                                       // enough to keep the suite under its time budget

  // The control. Without it, "the capped run took 0.42 s" proves nothing -- it could be
  // the transfer's natural speed. Same class, same code path, cap disabled.
  const double uncapped = transfer_mbps(0.0, kBytes);
  const double capped = transfer_mbps(kMbps, kBytes);
  REQUIRE(uncapped > 0);
  REQUIRE(capped > 0);
  std::printf("    note: %zu bytes: uncapped %8.1f Mbit/s, capped %6.2f Mbit/s "
              "(configured %.1f, %.1f%% of target)\n",
              kBytes, uncapped, capped, kMbps, 100.0 * capped / kMbps);

  // The bucket starts empty, so the measured rate can only come in at or below the
  // ceiling; the 15% headroom is for clock resolution on a short run, not for a burst.
  CHECK_LE(capped, kMbps * 1.15);
  // ...and it must not be pathologically slow either: pacing overhead is ~1.5% per 16 KiB
  // slice, so anything below 60% of the target means the shaper is losing time somewhere.
  CHECK_GE(capped, kMbps * 0.6);
  // The control has to be far above the cap or the cap was not what slowed the transfer.
  CHECK_GT(uncapped, kMbps * 3.0);
}

// ---------------------------------------------------------------------------
// FaultLink: injected failures at named points
// ---------------------------------------------------------------------------

TEST(fault_link_with_nothing_armed_is_transparent) {
  // MemoryLink with a 4 KiB chunk limit: a transport that always transfers less than
  // asked, so the wrapper is exercised against the short-transfer behaviour rather than
  // against an idealised one.
  auto pr = MemoryLink::make_pair(4096);
  std::shared_ptr<MemoryLink> ma = pr.first, mb = pr.second;
  FaultPlan plan;  // nothing armed -- the production configuration
  auto fl = std::make_shared<FaultLink>(ma, &plan, FaultPoint::kMidPayloadEarly);

  constexpr size_t kN = 64u * 1024;
  std::vector<uint8_t> payload(kN);
  Rng rng(testing::seed() ^ 0x515151ull);
  rng.fill(payload);

  std::vector<uint8_t> got(kN, 0);
  std::atomic<bool> rx_ok{false};
  std::thread rx([&] { rx_ok.store(read_exact(*mb, got.data(), got.size()).ok()); });
  const bool ok = write_all(*fl, payload.data(), payload.size()).ok();
  CHECK(ok);
  if (!ok) fl->close();
  rx.join();

  CHECK(rx_ok.load());
  CHECK(got == payload);
  CHECK(!fl->dropped());
  CHECK(fl->is_open());
  CHECK_EQ(fl->bytes_out(), uint64_t{kN});
  CHECK_EQ(fl->bytes_through(), uint64_t{kN});
  CHECK_EQ(plan.fire_count(FaultPoint::kMidPayloadEarly), uint64_t{0});

  // A null plan is the same thing said a different way, and it is what the production
  // constructor call site will look like.
  auto pr2 = MemoryLink::make_pair();
  auto fl2 = std::make_shared<FaultLink>(pr2.first, nullptr, FaultPoint::kMidPayloadEarly);
  uint8_t one = 0x42, back = 0;
  CHECK(write_all(*fl2, &one, 1).ok());
  CHECK(read_exact(*pr2.second, &back, 1).ok());
  CHECK_EQ(back, one);
}

TEST(fault_link_drop_fires_once_and_the_peer_sees_reset) {
  // Three independent runs: "deterministically" means the same thing happens every time,
  // which one run cannot show (SPEC R3.5).
  for (int iter = 0; iter < 3; iter++) {
    TCTX("iter=" << iter);
    auto p = connected_pair(opts());
    CHECK(p.client && p.server);
    if (!p.client || !p.server) break;

    FaultPlan plan;
    plan.arm(FaultPoint::kMidPayloadEarly, FaultKind::kDropLink);
    auto fl = std::make_shared<FaultLink>(p.client, &plan, FaultPoint::kMidPayloadEarly);

    std::atomic<int> peer_code{-1};
    std::thread peer([&] {
      uint8_t sink[256];
      for (;;) {
        auto r = p.server->read_some(sink, sizeof(sink));
        if (!r.ok()) {
          peer_code.store(static_cast<int>(r.error().code));
          return;
        }
      }
    });

    uint8_t byte = 0x7E;
    auto w1 = fl->write_some(&byte, 1);
    CHECK(!w1.ok());
    if (!w1.ok()) CHECK_EQ(code_name(w1.error()), code_name(Err::kReset));
    CHECK(fl->dropped());
    // If the abortive close had degraded to an orderly one, the peer would see kClosed
    // and this test would be quietly measuring the opposite of what it claims.
    CHECK(!fl->drop_was_degraded());
    CHECK(!fl->is_open());
    CHECK_EQ(plan.fire_count(FaultPoint::kMidPayloadEarly), uint64_t{1});

    // A second operation must not re-fire the point: a fault that fires on every retry
    // turns "recovers cleanly" into an infinite loop rather than a test (fault.h).
    auto w2 = fl->write_some(&byte, 1);
    CHECK(!w2.ok());
    if (!w2.ok()) CHECK_EQ(code_name(w2.error()), code_name(Err::kReset));
    CHECK_EQ(plan.fire_count(FaultPoint::kMidPayloadEarly), uint64_t{1});

    peer.join();
    CHECK_EQ(code_name(static_cast<Err>(peer_code.load())), code_name(Err::kReset));
  }
}

TEST(fault_link_drop_after_bytes_fires_at_the_configured_offset) {
  auto p = connected_pair(opts());
  REQUIRE(p.client && p.server);

  FaultPlan plan;  // nothing armed: this drop is byte-triggered, which is the form SPEC
                   // R2.4's "drop at a randomized offset" needs
  auto fl = std::make_shared<FaultLink>(p.client, &plan, FaultPoint::kMidPayloadLate);
  constexpr uint64_t kDropAt = 4096;
  constexpr size_t kSlice = 512;
  fl->set_drop_after_bytes(kDropAt);

  std::atomic<int> peer_code{-1};
  std::thread peer([&] {
    uint8_t sink[1024];
    for (;;) {
      auto r = p.server->read_some(sink, sizeof(sink));
      if (!r.ok()) {
        peer_code.store(static_cast<int>(r.error().code));
        return;
      }
    }
  });

  std::vector<uint8_t> slice(kSlice, 0x11);
  uint64_t sent = 0;
  Err code = Err::kOk;
  for (int i = 0; i < 64; i++) {
    auto r = write_all(*fl, slice.data(), slice.size());
    if (!r.ok()) {
      code = r.error().code;
      break;
    }
    sent += kSlice;
  }
  CHECK_EQ(code_name(code), code_name(Err::kReset));
  CHECK_GE(sent, kDropAt);              // not early
  CHECK_LT(sent, kDropAt + kSlice);     // and not late: it fires on the op that crosses
  CHECK(fl->dropped());
  CHECK(!fl->drop_was_degraded());
  CHECK_EQ(fl->bytes_through(), sent);
  std::printf("    note: armed at %llu bytes, dropped after %llu delivered\n",
              static_cast<unsigned long long>(kDropAt), static_cast<unsigned long long>(sent));

  peer.join();
  // The peer may have received fewer bytes than we sent -- an RST discards whatever was
  // still queued -- but what it must NOT see is a clean end of stream, because that is
  // the case SPEC 3.7 treats as "the transfer finished".
  CHECK_EQ(code_name(static_cast<Err>(peer_code.load())), code_name(Err::kReset));
}

TEST(fault_link_io_error_is_reported_and_the_link_survives) {
  auto pr = MemoryLink::make_pair();
  FaultPlan plan;
  plan.arm(FaultPoint::kAfterNeed, FaultKind::kIoError);
  auto fl = std::make_shared<FaultLink>(pr.first, &plan, FaultPoint::kAfterNeed);

  uint8_t byte = 0x33;
  auto r = fl->write_some(&byte, 1);
  CHECK(!r.ok());
  if (!r.ok()) CHECK_EQ(code_name(r.error()), code_name(Err::kFaultInjected));

  // kIoError is the "the syscall failed but the connection is fine" case: the link must
  // still be usable, which is what distinguishes it from kDropLink.
  CHECK(fl->is_open());
  CHECK(!fl->dropped());
  CHECK_EQ(plan.fire_count(FaultPoint::kAfterNeed), uint64_t{1});

  uint8_t back = 0;
  CHECK(write_all(*fl, &byte, 1).ok());
  CHECK(read_exact(*pr.second, &back, 1).ok());
  CHECK_EQ(back, byte);
}

TEST(fault_link_corrupt_flips_exactly_one_bit_in_flight) {
  auto pr = MemoryLink::make_pair();  // no chunk limit: one write_some carries the payload
  FaultPlan plan;
  plan.arm(FaultPoint::kMidPayloadEarly, FaultKind::kCorrupt);
  auto fl = std::make_shared<FaultLink>(pr.first, &plan, FaultPoint::kMidPayloadEarly);

  constexpr size_t kN = 1024;
  std::vector<uint8_t> payload(kN);
  Rng rng(testing::seed() ^ 0xC0FFEEull);
  rng.fill(payload);
  const std::vector<uint8_t> original = payload;

  std::vector<uint8_t> got(kN, 0);
  std::atomic<bool> rx_ok{false};
  std::thread rx([&] { rx_ok.store(read_exact(*pr.second, got.data(), got.size()).ok()); });
  const bool ok = write_all(*fl, payload.data(), payload.size()).ok();
  CHECK(ok);
  if (!ok) fl->close();
  rx.join();
  REQUIRE(rx_ok.load());

  // The caller's buffer is a frame this node may still need; corrupting it in place would
  // be a bug in the injector that looked like a bug in the protocol.
  CHECK(payload == original);

  size_t differing = 0, index = 0;
  uint8_t delta = 0;
  for (size_t i = 0; i < kN; i++) {
    if (got[i] != payload[i]) {
      differing++;
      index = i;
      delta = static_cast<uint8_t>(got[i] ^ payload[i]);
    }
  }
  CHECK_EQ(differing, size_t{1});
  CHECK_EQ(delta, uint8_t{0x01});  // a single-bit flip: the hardest case for a checksum
  std::printf("    note: corrupted byte %zu of %zu, xor delta 0x%02x\n", index, kN, delta);

  // The point was armed for one firing, so the next write must cross intact -- otherwise
  // a fault test could never observe the recovery it exists to check.
  std::vector<uint8_t> second(64, 0xEE), second_got(64, 0);
  std::atomic<bool> rx2_ok{false};
  std::thread rx2([&] {
    rx2_ok.store(read_exact(*pr.second, second_got.data(), second_got.size()).ok());
  });
  CHECK(write_all(*fl, second.data(), second.size()).ok());
  rx2.join();
  CHECK(rx2_ok.load());
  CHECK(second_got == second);
  CHECK_EQ(plan.fire_count(FaultPoint::kMidPayloadEarly), uint64_t{1});
}

// ---------------------------------------------------------------------------
// T5 adversarial pass -- tests written to BREAK the three links above
// ---------------------------------------------------------------------------

namespace {

// Bulk-transfers `bytes` from a raw sender into a WanLink-wrapped receiver and returns
// the wall time until the last byte is delivered to the caller. Returns -1 on failure.
//
// The receiver is the wrapped end because SPEC 3.8's delay lives on the READ side. No
// bandwidth cap is configured, so the ONLY thing this measures is what the latency model
// costs a stream: physically, a fixed one-way delay makes the first byte late by rtt/2 and
// costs the rest of the transfer nothing.
double bulk_receive_ms(double rtt_ms, size_t bytes) {
  auto p = connected_pair(opts());
  if (!p.client || !p.server) return -1;

  WanLink::Params par;
  par.rtt_ms = rtt_ms;
  auto rx = std::make_shared<WanLink>(p.server, par);

  std::vector<uint8_t> payload(bytes, 0x5A);
  std::atomic<bool> tx_ok{false};
  std::thread tx([&] { tx_ok.store(write_all(*p.client, payload.data(), payload.size()).ok()); });

  std::vector<uint8_t> in(bytes, 0);
  const auto t0 = Clock::now();
  const bool ok = read_exact(*rx, in.data(), in.size()).ok();
  const double ms = ms_since(t0);
  if (!ok) rx->close();
  tx.join();
  if (!ok || !tx_ok.load() || in != payload) return -1;
  return ms;
}

}  // namespace

// The emulator must add LATENCY, not a throughput ceiling that scales with it.
//
// This is the read-side twin of the mistake the write side was designed to avoid. The
// delay line holds one slice at a time: it pulls at most kRxSliceBytes from the inner
// link, withholds them for rtt/2, and only then pulls again -- so a bulk stream is
// serialized to one slice per half-RTT and the emulated link tops out at
// kRxSliceBytes/(rtt/2), which is 5 Mbit/s at a 200 ms RTT no matter what the real
// transport can do. bench/rtt_curve (SPEC R1.6) would then be plotting the emulator's own
// ceiling and calling it the protocol's behaviour -- the exact failure SPEC 3.2 warns
// about, manufactured by the measuring instrument.
//
// The assertion that cannot pass by accident is the DIFFERENCE between two RTTs: a fixed
// one-way delay makes a fixed-size transfer later by exactly the extra half-RTT (20 ms
// here), while a per-slice delay makes it later by that times the number of slices.
TEST(wan_link_latency_does_not_become_a_throughput_ceiling) {
  constexpr size_t kBytes = 1u << 20;  // 16 slices of the 64 KiB the delay line holds
  const double t10 = bulk_receive_ms(10.0, kBytes);
  const double t50 = bulk_receive_ms(50.0, kBytes);
  REQUIRE(t10 > 0);
  REQUIRE(t50 > 0);

  const double mbps10 = static_cast<double>(kBytes) * 8.0 / (t10 / 1000.0) / 1e6;
  const double mbps50 = static_cast<double>(kBytes) * 8.0 / (t50 / 1000.0) / 1e6;
  std::printf("    note: %zu bytes received through rtt=10ms in %7.1f ms (%8.1f Mbit/s), "
              "rtt=50ms in %7.1f ms (%8.1f Mbit/s)\n",
              kBytes, t10, mbps10, t50, mbps50);

  // A fixed delay costs one half-RTT of head-of-line time and nothing else, so raising the
  // configured RTT by 40 ms owes exactly 20 ms more here (measured: 18-25 ms). A per-slice
  // delay line owes 16x that, and 256x on a 16 MiB transfer -- it measured 314-377 ms.
  //
  // The budget on top is three extra one-way delays at the 50 ms row. That is not slack
  // for its own sake: the emulator decides per slice whether bytes were already in flight
  // (see wan_link.h) and errs CONSERVATIVELY under scheduling pressure, so a stray slice
  // can pay a 25 ms delay it did not owe. Three of those is generous for a loaded
  // container and still leaves this assertion catching the defect it exists for by more
  // than a factor of three.
  const double extra = t50 - t10;
  std::printf("    note: extra time for +40 ms of RTT: %7.1f ms (a fixed delay owes 20 ms)\n",
              extra);
  CHECK_LT(extra, 20.0 + 3 * 25.0);

  // And an absolute floor, so the test still means something if both rows are slow. The
  // broken version measured 18.9 Mbit/s here; 60 keeps three times that margin while
  // surviving the same stray slices the bound above allows for.
  CHECK_GT(mbps50, 60.0);
}

// A short write must not silently swallow an injected corruption.
//
// SPEC 2.5's headline socket fact is that a write moves fewer bytes than asked -- this
// suite measures 57 344 of 4 194 304 on a stalled socket. FaultLink flips a bit at the
// MIDPOINT of the caller's buffer, so whenever the inner link accepts fewer than half the
// bytes, the flipped byte is never transmitted and write_all resends the tail from the
// caller's untouched buffer. The fault fired, fire_count says 1, and NOTHING was
// corrupted: a fault that quietly became no fault, which is the failure mode
// drop_was_degraded() exists to prevent on the other injection kind.
//
// The existing corruption test uses a MemoryLink with no chunk limit and says so ("one
// write_some carries the payload"), which is exactly the case that hides this.
TEST(fault_link_corrupt_still_lands_when_the_write_comes_back_short) {
  for (size_t limit : {size_t{1}, size_t{7}, size_t{64}, size_t{511}}) {
    TCTX("chunk_limit=" << limit);
    auto pr = MemoryLink::make_pair(limit);
    FaultPlan plan;
    plan.arm(FaultPoint::kMidPayloadEarly, FaultKind::kCorrupt);
    auto fl = std::make_shared<FaultLink>(pr.first, &plan, FaultPoint::kMidPayloadEarly);

    constexpr size_t kN = 1024;
    std::vector<uint8_t> payload(kN);
    Rng rng(testing::seed() ^ 0xB17F11ull);
    rng.fill(payload);
    const std::vector<uint8_t> original = payload;

    std::vector<uint8_t> got(kN, 0);
    std::atomic<bool> rx_ok{false};
    std::thread rx([&] { rx_ok.store(read_exact(*pr.second, got.data(), got.size()).ok()); });
    const bool ok = write_all(*fl, payload.data(), payload.size()).ok();
    CHECK(ok);
    if (!ok) fl->close();
    rx.join();
    REQUIRE(rx_ok.load());

    CHECK(payload == original);  // never in place: the caller may still need the frame

    size_t differing = 0, index = 0;
    uint8_t delta = 0;
    for (size_t i = 0; i < kN; i++) {
      if (got[i] != payload[i]) {
        differing++;
        index = i;
        delta = static_cast<uint8_t>(got[i] ^ payload[i]);
      }
    }
    std::printf("    note: chunk_limit=%3zu -> %zu byte(s) actually corrupted on the wire "
                "(index %zu, delta 0x%02x)\n",
                limit, differing, index, delta);
    // Exactly one bit, exactly once: the corruption must reach the peer even though no
    // single write_some carried the whole buffer.
    CHECK_EQ(differing, size_t{1});
    CHECK_EQ(delta, uint8_t{0x01});
    CHECK_EQ(plan.fire_count(FaultPoint::kMidPayloadEarly), uint64_t{1});
  }
}

// Absurd emulator parameters must be refused or clamped, never turned into undefined
// behaviour or an unbounded sleep.
//
// WanLink::Params is not wire data, so this is not S12 -- it is `--rtt` and `--bw` from
// SPEC 4.2's command line, which is to say a human, which is to say a typo. Every one of
// these values reaches a double -> chrono::nanoseconds conversion, and a floating value
// outside int64's range converts with UNDEFINED behaviour (UBSan calls it
// float-cast-overflow). What comes out the other side is a garbage duration: negative and
// the emulator silently applies no delay at all, positive and sleep_until parks the
// process for centuries. Both are worse than an error, and the second is indistinguishable
// from a deadlock in the protocol above.
TEST(wan_link_absurd_parameters_do_not_become_undefined_behaviour) {
  const double kInf = std::numeric_limits<double>::infinity();
  const double kNan = std::numeric_limits<double>::quiet_NaN();
  struct Case {
    const char* what;
    double rtt_ms, bw_mbps, jitter_ms;
  };
  const Case cases[] = {
      {"rtt beyond int64 nanoseconds", 1e300, 0, 0},
      {"rtt infinite", kInf, 0, 0},
      {"rtt NaN", kNan, 0, 0},
      {"rtt negative", -50.0, 0, 0},
      {"jitter beyond int64 nanoseconds", 10.0, 0, 1e300},
      {"jitter NaN", 10.0, 0, kNan},
      {"bandwidth so small one slice takes millennia", 0, 1e-12, 0},
      {"bandwidth NaN", 0, kNan, 0},
      {"bandwidth infinite", 0, kInf, 0},
      {"bandwidth negative", 0, -20.0, 0},
  };

  for (const Case& c : cases) {
    TCTX("case=" << c.what);
    auto pr = MemoryLink::make_pair();
    WanLink::Params par;
    par.rtt_ms = c.rtt_ms;
    par.bandwidth_mbps = c.bw_mbps;
    par.jitter_ms = c.jitter_ms;
    par.seed = testing::seed();
    auto tx = std::make_shared<WanLink>(pr.first, par);
    auto rx = std::make_shared<WanLink>(pr.second, par);

    // Every case here is out of range, and the link must SAY so. A clamp nobody can
    // observe is worse than no clamp: the benchmark header would print the configuration
    // that was asked for while the run emulated something else.
    CHECK(WanLink::params_out_of_range(par));
    CHECK(tx->params_were_clamped());
    // ...and the effective parameters it reports must be ones it can actually honour.
    CHECK(!WanLink::params_out_of_range(tx->params()));

    // The checked factory is what SPEC 4.2's CLI should call: a mistyped flag has to be an
    // error at startup, not a silently different link.
    auto checked = WanLink::create(pr.first, par);
    CHECK(!checked.ok());
    if (!checked.ok()) CHECK_EQ(code_name(checked.error()), code_name(Err::kInvalidArgument));

    // Now move a byte through the clamped link, on a watchdog: the failure mode this
    // catches is a park so long it is indistinguishable from a deadlock, and a hung test
    // cannot report itself. Cases whose clamped configuration is legitimately slow are
    // skipped rather than waited on -- what matters for those is that the delay is FINITE,
    // which wan_link_ms_to_duration_saturates proves directly.
    const double budget_ms = tx->params().rtt_ms + 2 * tx->params().jitter_ms;
    if (budget_ms > 200.0) {
      std::printf("    note: %-42s clamped to rtt=%.0f ms jitter=%.0f ms (finite; not "
                  "round-tripped)\n",
                  c.what, tx->params().rtt_ms, tx->params().jitter_ms);
      continue;
    }

    std::atomic<bool> done{false};
    uint8_t sent = 0xA5, got = 0;
    std::thread worker([&] {
      if (write_all(*tx, &sent, 1).ok()) (void)read_exact(*rx, &got, 1).ok();
      done.store(true, std::memory_order_release);
    });
    const auto t0 = Clock::now();
    const double deadline_ms = budget_ms * 1.5 + 2000.0;
    while (!done.load(std::memory_order_acquire) && ms_since(t0) < deadline_ms) {
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    const bool finished = done.load(std::memory_order_acquire);
    CHECK(finished);
    if (!finished) {
      // Detaching leaks the thread, but joining a thread parked until the heat death of
      // the universe would hang the whole suite instead of failing this one case.
      worker.detach();
      continue;
    }
    worker.join();
    CHECK_EQ(got, sent);
    std::printf("    note: %-42s survived in %6.1f ms\n", c.what, ms_since(t0));
  }
}

// The conversion the case above is really about, tested where it lives.
//
// Every absurd parameter ends here, and the two things that must hold are that the result
// is FINITE and that `now + result` is still computable. The second is the one that bit:
// on aarch64 the out-of-range double->int64 conversion saturates to INT64_MAX rather than
// producing junk, so the conversion itself looks harmless and the signed overflow happens
// one line later inside sleep_until. This test does that addition explicitly so UBSan is
// standing exactly where the fault was.
TEST(wan_link_ms_to_duration_saturates_instead_of_overflowing) {
  const double kInf = std::numeric_limits<double>::infinity();
  const double kNan = std::numeric_limits<double>::quiet_NaN();
  const double inputs[] = {0.0,   -1.0,  -1e300, kNan,  kInf,  -kInf,
                           1e300, 1e18,  1e9,    10.0,  0.001, std::numeric_limits<double>::max()};
  const auto now = Clock::now();
  for (double ms : inputs) {
    TCTX("ms=" << ms);
    const auto d = wan_detail::ms_to_duration(ms);
    CHECK_GE(d.count(), int64_t{0});           // never negative: a negative delay is no delay
    CHECK_LE(d.count(), int64_t{100000000000000000});  // the 1e17 ns ceiling
    const auto deadline = now + d;             // the addition that overflowed
    CHECK_GE(deadline, now);
    // Finite values inside the range must still be exact to the nanosecond: the clamp must
    // not cost the emulator its resolution.
    if (ms > 0.0 && ms < 1e6) CHECK_EQ(d.count(), static_cast<int64_t>(ms * 1e6));
  }
  std::printf("    note: ms_to_duration(1e300) = %lld ns, ms_to_duration(NaN) = %lld ns\n",
              static_cast<long long>(wan_detail::ms_to_duration(1e300).count()),
              static_cast<long long>(wan_detail::ms_to_duration(kNan).count()));
}

// SPEC 4.1's authoritative counter, read while the link is busy -- which is what a
// progress meter or bench/rtt_curve does, and what SPEC 3.6's two-thread socket makes
// unavoidable.
//
// This is the supported half of TcpLink's threading contract: one sender thread, one
// reader thread, and somebody watching bytes_out()/bytes_in(). With the counters as plain
// `uint64_t` it is a data race in the C++ sense -- TSan reports it -- which means the
// number every bandwidth claim in this project is read from was formally undefined while
// it was worth reading. The fix is relaxed atomics; the assertion below is conservation:
// the counters must end at exactly what the two threads moved, no torn or lost updates.
TEST(tcp_link_counters_are_safe_to_read_while_the_link_is_busy) {
  auto p = connected_pair(opts());
  REQUIRE(p.client && p.server);

  constexpr size_t kChunk = 4096;
  constexpr int kRounds = 64;
  std::thread peer([&] {
    std::vector<uint8_t> buf(kChunk);
    for (int i = 0; i < kRounds; i++) {
      if (!read_exact(*p.server, buf.data(), buf.size()).ok()) return;
      if (!write_all(*p.server, buf.data(), buf.size()).ok()) return;
    }
  });

  std::atomic<bool> writer_ok{false}, reader_ok{false};
  std::vector<uint8_t> out(kChunk, 0x71);
  std::thread writer([&] {
    for (int i = 0; i < kRounds; i++) {
      if (!write_all(*p.client, out.data(), out.size()).ok()) return;
    }
    writer_ok.store(true, std::memory_order_release);
  });
  std::thread reader([&] {
    std::vector<uint8_t> in(kChunk);
    for (int i = 0; i < kRounds; i++) {
      if (!read_exact(*p.client, in.data(), in.size()).ok()) return;
    }
    reader_ok.store(true, std::memory_order_release);
  });

  // The concurrent observer. Monotonicity is asserted as it goes: a torn read of a
  // 64-bit counter would show up here as a value that went backwards.
  uint64_t last_out = 0, last_in = 0, samples = 0;
  while (!(writer_ok.load(std::memory_order_acquire) &&
           reader_ok.load(std::memory_order_acquire))) {
    const uint64_t o = p.client->bytes_out(), i = p.client->bytes_in();
    CHECK_GE(o, last_out);
    CHECK_GE(i, last_in);
    last_out = o;
    last_in = i;
    samples++;
    std::this_thread::yield();
  }
  writer.join();
  reader.join();
  peer.join();

  CHECK(writer_ok.load());
  CHECK(reader_ok.load());
  CHECK_EQ(p.client->bytes_out(), uint64_t{kChunk} * kRounds);
  CHECK_EQ(p.client->bytes_in(), uint64_t{kChunk} * kRounds);
  std::printf("    note: %llu concurrent samples of the counters while %d KiB moved each way\n",
              static_cast<unsigned long long>(samples), int(kChunk * kRounds / 1024));
}

// The drop fires from whichever thread crosses the byte count -- and SPEC 3.6 puts TWO
// threads on one socket.
//
// This is the arrangement the fault matrix (SPEC R3.2, T10) will run: a sender thread owns
// the socket for writing, a reader thread owns it for reading, and FaultLink counts bytes
// in BOTH directions, so a byte that arrives on the READER's thread can be the one that
// trips set_drop_after_bytes() and calls close_abruptly() on the socket the SENDER is at
// that instant inside ::send() on.
//
// What that costs, if the descriptor is an ordinary `int`: a data race on fd_ in the
// C++ sense (undefined behaviour, TSan-reportable), and behind it the real hazard --
// close() releases the descriptor NUMBER, so a concurrent send() can be aimed at whatever
// the kernel has since handed to another thread. Making fd_ atomic removes the first
// entirely and narrows the second to the window inside one syscall; the residual is
// documented in tcp_link.h rather than papered over, because it is a property of closing a
// descriptor another thread is using, not of this class.
//
// What this test asserts is the OBSERVABLE contract, since the hazard itself cannot be
// removed: whichever thread loses the race, neither side may end with Err::kClosed. A
// killed link that reports "the peer finished" is the one mistranslation SPEC 3.7 cannot
// survive -- it is how a truncated transfer gets committed as a complete one (S5). The
// losing thread really can come back kClosed from the transport (its descriptor was taken
// away mid-flight), so FaultLink translates it: the injector knows the link was killed.
//
// NOT RUN UNDER TSan, and the reason is the finding rather than an excuse: TSan reports
// the close() of a descriptor another thread is blocked in recv() on, which is exactly
// what this test provokes on purpose and exactly what tcp_link.h documents as
// unfixable-in-this-layer. Suppressing it would hide a true report; running the case
// without TSan keeps the code assertions, which are what this test is for.
#if defined(__SANITIZE_THREAD__)
TEST(fault_link_drop_from_the_other_thread_never_reports_closed) {
  std::printf("    note: skipped under TSan on purpose -- this case closes a descriptor a "
              "second thread is blocked on, which TSan correctly reports; see tcp_link.h's "
              "threading contract\n");
}
#else
TEST(fault_link_drop_from_the_other_thread_never_reports_closed) {
  for (int iter = 0; iter < 3; iter++) {
    TCTX("iter=" << iter);
    auto p = connected_pair(opts());
    REQUIRE(p.client && p.server);

    FaultPlan plan;  // byte-triggered, so the firing thread is whichever one gets there
    auto fl = std::make_shared<FaultLink>(p.client, &plan, FaultPoint::kMidPayloadLate);
    fl->set_drop_after_bytes(192u * 1024);

    std::thread peer([&] {
      std::vector<uint8_t> buf(8192);
      for (;;) {
        auto r = p.server->read_some(buf.data(), buf.size());
        if (!r.ok()) return;
        if (!write_all(*p.server, buf.data(), *r).ok()) return;
      }
    });

    std::atomic<int> writer_code{-1}, reader_code{-1};
    std::vector<uint8_t> out(4096, 0x5C);
    std::thread writer([&] {
      for (;;) {
        auto r = fl->write_some(out.data(), out.size());
        if (!r.ok()) {
          writer_code.store(static_cast<int>(r.error().code), std::memory_order_release);
          return;
        }
      }
    });
    std::thread reader([&] {
      std::vector<uint8_t> in(4096);
      for (;;) {
        auto r = fl->read_some(in.data(), in.size());
        if (!r.ok()) {
          reader_code.store(static_cast<int>(r.error().code), std::memory_order_release);
          return;
        }
      }
    });

    // The progress meter: SPEC 4.1's authoritative counter, read while the transfer runs.
    // The sampling itself is the exercise -- it is what makes the counters be read while
    // they are being written. How MANY samples land is a property of the scheduler, not of
    // the code under test, so nothing is asserted about it; on a loaded machine both
    // threads can finish before this loop gets its first turn.
    uint64_t samples = 0;
    const auto t0 = Clock::now();
    do {
      (void)(fl->bytes_out() + fl->bytes_in());
      samples++;
      std::this_thread::yield();
    } while ((writer_code.load(std::memory_order_acquire) < 0 ||
              reader_code.load(std::memory_order_acquire) < 0) &&
             ms_since(t0) < 20000.0);
    writer.join();
    reader.join();
    p.client->close();
    p.server->close();
    peer.join();

    CHECK(fl->dropped());
    CHECK(!fl->drop_was_degraded());
    // Both sides must end with a code, and neither may end with a clean kClosed: this link
    // was killed, and SPEC 3.7 resumes on exactly that distinction.
    CHECK_NE(writer_code.load(), -1);
    CHECK_NE(reader_code.load(), -1);
    CHECK_NE(code_name(static_cast<Err>(writer_code.load())), code_name(Err::kClosed));
    CHECK_NE(code_name(static_cast<Err>(reader_code.load())), code_name(Err::kClosed));
    // Read once more now that everything has stopped: the counters must account for the
    // traffic that actually crossed (SPEC 4.1), whether or not the sampler saw it happen.
    const uint64_t total = fl->bytes_out() + fl->bytes_in();
    CHECK_GT(total, uint64_t{0});
    if (iter == 0) {
      std::printf("    note: %llu concurrent samples over %llu bytes; writer ended '%s', "
                  "reader ended '%s' after %llu bytes through the injector\n",
                  static_cast<unsigned long long>(samples),
                  static_cast<unsigned long long>(total),
                  code_name(static_cast<Err>(writer_code.load())).c_str(),
                  code_name(static_cast<Err>(reader_code.load())).c_str(),
                  static_cast<unsigned long long>(fl->bytes_through()));
    }
  }
}
#endif  // __SANITIZE_THREAD__

// abort_link()'s unwrapping, which nothing exercised.
//
// FaultLink(WanLink(TcpLink)) is THE stack a fault test over an emulated WAN runs on
// (SPEC 3.8), and reaching the real socket through it is a recursive dynamic_cast that no
// existing test covers -- every drop test wraps a TcpLink or a MemoryLink directly. If the
// recursion were wrong the drop would degrade to an orderly close, the peer would see
// kClosed, and SPEC 3.7's resume would read a killed link as a finished transfer (S5).
//
// The second half is the one that proves the honesty mechanism itself can fire: every
// other test asserts drop_was_degraded() is FALSE, which says nothing unless something
// makes it true. A link with no abortive close of its own must degrade AND say so.
TEST(fault_link_drop_unwraps_a_wan_link_and_admits_it_when_it_cannot) {
  {
    auto p = connected_pair(opts());
    REQUIRE(p.client && p.server);
    WanLink::Params par;
    par.rtt_ms = 10.0;
    par.seed = testing::seed();
    auto wan = std::make_shared<WanLink>(p.client, par);

    FaultPlan plan;
    plan.arm(FaultPoint::kMidPayloadEarly, FaultKind::kDropLink);
    auto fl = std::make_shared<FaultLink>(wan, &plan, FaultPoint::kMidPayloadEarly);

    std::atomic<int> peer_code{-1};
    std::thread peer([&] {
      uint8_t sink[256];
      for (;;) {
        auto r = p.server->read_some(sink, sizeof(sink));
        if (!r.ok()) {
          peer_code.store(static_cast<int>(r.error().code), std::memory_order_release);
          return;
        }
      }
    });

    uint8_t byte = 0x5D;
    auto w = fl->write_some(&byte, 1);
    CHECK(!w.ok());
    if (!w.ok()) CHECK_EQ(code_name(w.error()), code_name(Err::kReset));
    // The whole point: the RST came out of the socket two layers down.
    CHECK(!fl->drop_was_degraded());
    peer.join();
    CHECK_EQ(code_name(static_cast<Err>(peer_code.load())), code_name(Err::kReset));
  }

  {
    // CountingLink is an ordinary Link with no abortive close, standing in for any future
    // wrapper someone slips underneath the injector.
    auto p = connected_pair(opts());
    REQUIRE(p.client && p.server);
    auto plain = std::make_shared<CountingLink>(p.client);
    FaultPlan plan;
    plan.arm(FaultPoint::kAfterNeed, FaultKind::kDropLink);
    auto fl = std::make_shared<FaultLink>(plain, &plan, FaultPoint::kAfterNeed);

    uint8_t byte = 0x11;
    auto w = fl->write_some(&byte, 1);
    CHECK(!w.ok());
    CHECK(fl->dropped());
    // It could not produce an RST, and it must say so rather than let a drop test quietly
    // measure a FIN and report coverage the matrix does not have.
    CHECK(fl->drop_was_degraded());
    uint8_t sink = 0;
    auto r = p.server->read_some(&sink, 1);
    CHECK(!r.ok());
    if (!r.ok()) {
      std::printf("    note: degraded drop -> peer saw '%s' (and drop_was_degraded() is true)\n",
                  code_name(r.error()).c_str());
      CHECK_EQ(code_name(r.error()), code_name(Err::kClosed));
    }
  }
}

// Sizes at and around every boundary the three links have: zero, one, exactly the WanLink
// delay line's 64 KiB slice, one past it, and one under. Run under ASan this is the test
// that would catch an off-by-one in the slice arithmetic -- rx_pos_/rx_len_ index a heap
// buffer, and `rx_len_ - rx_pos_` is unsigned, so an inverted comparison there is not a
// wrong answer but an out-of-bounds read of about 18 exabytes.
TEST(links_are_exact_at_every_size_boundary) {
  constexpr size_t kSlice = 64u * 1024;  // WanLink::kRxSliceBytes, which is private
  const size_t sizes[] = {1, 2, 63, 64, 4095, 4096, kSlice - 1, kSlice, kSlice + 1, 3 * kSlice + 7};
  Rng rng(testing::seed() ^ 0xB0111Dull);

  for (size_t n : sizes) {
    TCTX("bytes=" << n);
    auto p = connected_pair(opts());
    REQUIRE(p.client && p.server);
    WanLink::Params par;
    par.seed = testing::seed();  // no delay, no cap: the SLICING is what is under test
    auto tx = std::make_shared<WanLink>(p.client, par);
    auto rx = std::make_shared<WanLink>(p.server, par);
    FaultPlan plan;  // nothing armed: the injector must be transparent at every size
    auto ftx = std::make_shared<FaultLink>(tx, &plan, FaultPoint::kMidPayloadEarly);

    std::vector<uint8_t> payload(n);
    rng.fill(payload);
    std::vector<uint8_t> got(n, 0);
    std::atomic<bool> rx_ok{false};
    std::thread reader([&] { rx_ok.store(read_exact(*rx, got.data(), got.size()).ok()); });
    const bool ok = write_all(*ftx, payload.data(), payload.size()).ok();
    CHECK(ok);
    if (!ok) ftx->close();
    reader.join();
    CHECK(rx_ok.load());
    CHECK(got == payload);
    // The counters are delegated all the way down to the socket, so they must equal the
    // payload exactly -- a wrapper that counted its own view would drift here.
    CHECK_EQ(ftx->bytes_out(), uint64_t{n});
    CHECK_EQ(rx->bytes_in(), uint64_t{n});

    // n == 0 is a no-op on every layer and must not touch the buffer or the counters.
    uint8_t untouched = 0xC7;
    auto w0 = ftx->write_some(&untouched, 0);
    auto r0 = rx->read_some(&untouched, 0);
    CHECK(w0.ok());
    CHECK(r0.ok());
    if (w0.ok()) CHECK_EQ(*w0, size_t{0});
    if (r0.ok()) CHECK_EQ(*r0, size_t{0});
    CHECK_EQ(untouched, uint8_t{0xC7});
    CHECK_EQ(ftx->bytes_out(), uint64_t{n});
  }
  std::printf("    note: exact round trip at %zu sizes from 1 to %zu bytes across "
              "FaultLink/WanLink/TcpLink\n",
              sizeof(sizes) / sizeof(sizes[0]), sizes[sizeof(sizes) / sizeof(sizes[0]) - 1]);
}

// One flipped bit, wherever the buffer is smallest. n == 1 puts the midpoint at index 0,
// which is the index an off-by-one in the clamp would step past.
TEST(fault_link_corrupt_at_the_smallest_possible_buffer) {
  for (size_t n : {size_t{1}, size_t{2}, size_t{3}}) {
    TCTX("bytes=" << n);
    auto pr = MemoryLink::make_pair();
    FaultPlan plan;
    plan.arm(FaultPoint::kMidPayloadLate, FaultKind::kCorrupt);
    auto fl = std::make_shared<FaultLink>(pr.first, &plan, FaultPoint::kMidPayloadLate);

    std::vector<uint8_t> payload(n, 0x40), got(n, 0);
    std::atomic<bool> rx_ok{false};
    std::thread rx([&] { rx_ok.store(read_exact(*pr.second, got.data(), got.size()).ok()); });
    CHECK(write_all(*fl, payload.data(), payload.size()).ok());
    rx.join();
    REQUIRE(rx_ok.load());

    size_t differing = 0;
    for (size_t i = 0; i < n; i++) {
      if (got[i] != payload[i]) {
        differing++;
        CHECK_EQ(static_cast<uint8_t>(got[i] ^ payload[i]), uint8_t{0x01});
      }
    }
    CHECK_EQ(differing, size_t{1});
  }
}

namespace {

// A Link that reports MORE bytes than it was asked for. Nothing in the tree does this --
// the point is that nothing in the tree is supposed to, and every wrapper takes that
// number and uses it to index a buffer.
class LyingLink : public Link {
 public:
  // Three times, so the lie is large enough to push an index past the end of the caller's
  // buffer as well as past the end of the wrapper's own slice.
  Result<size_t> write_some(const uint8_t*, size_t n) override { return n * 3; }
  Result<size_t> read_some(uint8_t* p, size_t n) override {
    std::memset(p, 0x5B, n);  // it fills only what it legitimately can
    return n * 3;             // ...and then lies about it
  }
  void close() override {}
  bool is_open() const override { return true; }
  uint64_t bytes_out() const override { return 0; }
  uint64_t bytes_in() const override { return 0; }
  std::string describe() const override { return "lying"; }
};

}  // namespace

// A count from a lower layer is still an untrusted count.
//
// SPEC S7's rule is about the wire, but its content is "validate a length before you use
// it to bound a copy", and these wrappers use a length from another Link to do exactly
// that. WanLink's slice arithmetic (`rx_len_ - rx_pos_`) is unsigned, so an over-report
// makes the next memcpy read off the end of a 64 KiB heap buffer and hand the result to
// the caller; FaultLink's corrupt path uses the same number to index the CALLER's buffer
// and writes past its end. Both are heap overflows out of one unchecked comparison, which
// is why the check is one comparison as well. ASan is the oracle for this test.
TEST(links_reject_an_inner_link_that_over_reports_its_transfer) {
  {
    WanLink::Params par;
    par.rtt_ms = 1.0;
    auto wan = std::make_shared<WanLink>(std::make_shared<LyingLink>(), par);
    std::vector<uint8_t> buf(32, 0);
    // Drained in small reads: the over-report becomes rx_len_, and the delay line then
    // walks rx_pos_ right past the end of its own 64 KiB slice. The first call is where
    // the check belongs, but the loop is what makes ASan the judge rather than an opinion.
    Err code = Err::kOk;
    for (int i = 0; i < 4096; i++) {
      auto r = wan->read_some(buf.data(), buf.size());
      if (!r.ok()) {
        code = r.error().code;
        break;
      }
    }
    CHECK_EQ(code_name(code), code_name(Err::kIo));  // an error, not a heap over-read
  }
  {
    FaultPlan plan;
    plan.arm(FaultPoint::kMidPayloadEarly, FaultKind::kCorrupt);
    auto fl = std::make_shared<FaultLink>(std::make_shared<LyingLink>(), &plan,
                                          FaultPoint::kMidPayloadEarly);
    std::vector<uint8_t> buf(32, 0);
    auto r = fl->read_some(buf.data(), buf.size());  // the corrupt path indexes p[*r/2]
    CHECK(!r.ok());
    if (!r.ok()) CHECK_EQ(code_name(r.error()), code_name(Err::kIo));
  }
  {
    FaultPlan plan;  // nothing armed: the plain pass-through path
    auto fl = std::make_shared<FaultLink>(std::make_shared<LyingLink>(), &plan,
                                          FaultPoint::kMidPayloadEarly);
    std::vector<uint8_t> buf(32, 0);
    auto rr = fl->read_some(buf.data(), buf.size());
    CHECK(!rr.ok());
    // On the write side an over-report is not a memory error here but a silent truncation
    // upstairs: write_all would step its cursor past bytes that never left.
    auto rw = fl->write_some(buf.data(), buf.size());
    CHECK(!rw.ok());
    if (!rw.ok()) CHECK_EQ(code_name(rw.error()), code_name(Err::kIo));
  }
  std::printf("    note: an over-reporting inner link is refused by WanLink and FaultLink "
              "on both directions\n");
}

RUN_ALL()
