// T0 smoke suite.
//
// Three jobs:
//   1. Prove the harness itself works (a test framework whose failures are silent is
//      worse than none).
//   2. Verify the platform assumptions the on-wire and on-disk layouts rest on, before
//      any code depends on them.
//   3. Verify the *socket* behaviours SPEC S11 is written against. This is the part
//      that differs from project #1: a storage engine's dangerous syscalls are write
//      and fsync; a replication engine's are send, recv and close, and every one of
//      them has a failure mode that looks like success. Each CHECK below corresponds
//      to a sentence in the spec that would otherwise be folklore.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "test.h"
#include "wanrep/fsprobe.h"
#include "wanrep/types.h"

using namespace wanrep;

// ---------------------------------------------------------------------------
// 0. Small helpers
// ---------------------------------------------------------------------------

namespace {

// A connected TCP loopback pair. Real TCP, not socketpair(AF_UNIX): the behaviours we
// are pinning down here (RST vs FIN, SO_LINGER, buffer-driven short writes) are TCP
// behaviours, and AF_UNIX would answer a question we are not asking.
struct TcpPair {
  int client = -1;
  int server = -1;
  ~TcpPair() {
    if (client >= 0) ::close(client);
    if (server >= 0) ::close(server);
  }
};

// bufsize > 0 shrinks both send and receive buffers, which is how we force a short
// write deterministically instead of hoping for one.
bool make_tcp_pair(TcpPair& p, int bufsize = 0) {
  const int lst = ::socket(AF_INET, SOCK_STREAM, 0);
  if (lst < 0) return false;
  const int one = 1;
  if (::setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
    ::close(lst);
    return false;
  }
  if (bufsize > 0 &&
      ::setsockopt(lst, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) != 0) {
    ::close(lst);
    return false;  // must be set on the listener: the accepted socket inherits it
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;  // let the kernel pick a free port -- no fixed port, no flakiness
  if (::bind(lst, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
      ::listen(lst, 1) != 0) {
    ::close(lst);
    return false;
  }
  socklen_t alen = sizeof(addr);
  if (::getsockname(lst, reinterpret_cast<sockaddr*>(&addr), &alen) != 0) {
    ::close(lst);
    return false;
  }
  const int cli = ::socket(AF_INET, SOCK_STREAM, 0);
  if (cli < 0) {
    ::close(lst);
    return false;
  }
  if (bufsize > 0 &&
      ::setsockopt(cli, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) != 0) {
    ::close(cli);
    ::close(lst);
    return false;
  }
  if (::connect(cli, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(cli);
    ::close(lst);
    return false;
  }
  const int srv = ::accept(lst, nullptr, nullptr);
  ::close(lst);
  if (srv < 0) {
    ::close(cli);
    return false;
  }
  p.client = cli;
  p.server = srv;
  return true;
}

// A temporary directory that removes itself. The filesystem facts below need a real
// directory on the container's filesystem, not a mock.
struct TempDir {
  std::filesystem::path path;
  TempDir() {
    char tmpl[] = "/tmp/wanrep_t0_XXXXXX";
    if (::mkdtemp(tmpl) != nullptr) path = tmpl;
  }
  ~TempDir() {
    if (!path.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(path, ec);
    }
  }
};

bool write_file(const std::filesystem::path& p, const std::string& data) {
  const int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return false;
  const ssize_t n = ::write(fd, data.data(), data.size());
  ::close(fd);
  return n == static_cast<ssize_t>(data.size());
}

std::string read_file(const std::filesystem::path& p) {
  const int fd = ::open(p.c_str(), O_RDONLY);
  if (fd < 0) return {};
  char buf[256];
  const ssize_t n = ::read(fd, buf, sizeof(buf));
  ::close(fd);
  return n > 0 ? std::string(buf, static_cast<size_t>(n)) : std::string{};
}

volatile sig_atomic_t g_alarm_fired = 0;
void on_alarm(int) { g_alarm_fired = 1; }

}  // namespace

// ---------------------------------------------------------------------------
// 1. Harness sanity
// ---------------------------------------------------------------------------

TEST(harness_basic_checks_pass) {
  CHECK(true);
  CHECK_EQ(2 + 2, 4);
  CHECK_NE(1, 2);
  CHECK_LT(1, 2);
  CHECK_GE(2, 2);
}

TEST(harness_context_and_loops) {
  // If this ever fails, the TCTX string tells us *which* iteration -- the point of
  // having it at all.
  for (int i = 0; i < 4; i++) {
    TCTX("iter=" << i);
    CHECK_EQ(i * 2, i + i);
  }
}

TEST(harness_seed_is_stable_within_a_run) {
  CHECK_EQ(testing::seed(), testing::seed());
  CHECK_NE(testing::seed(), uint64_t{0});
}

// ---------------------------------------------------------------------------
// 2. Platform assumptions behind the wire and disk layouts (SPEC 3.2, 3.5)
// ---------------------------------------------------------------------------

// The frame header is defined little-endian and read by memcpy. On a big-endian host
// every length, offset and sequence number would be byte-swapped garbage -- and the
// magic would still match, so the corruption would be silent. Assert it.
TEST(platform_is_little_endian) {
  CHECK(std::endian::native == std::endian::little);
}

TEST(platform_byte_and_int_widths) {
  CHECK_EQ(CHAR_BIT, 8);
  CHECK_EQ(sizeof(uint64_t), size_t{8});
  CHECK_EQ(sizeof(uint32_t), size_t{4});
}

// types.h already static_asserts these, so a violation is a compile error. Repeating
// them at runtime puts the numbers in the test report, where a reader can see what the
// wire contract actually is without opening the header.
TEST(layout_frame_header_is_32_bytes_unpadded) {
  CHECK_EQ(sizeof(FrameHeader), size_t{32});
  CHECK_EQ(alignof(FrameHeader), size_t{8});
  CHECK_EQ(offsetof(FrameHeader, wire_len), size_t{8});
  CHECK_EQ(offsetof(FrameHeader, seq), size_t{16});
  CHECK_EQ(offsetof(FrameHeader, header_crc), size_t{28});
  // The header CRC must cover every byte before itself and no byte of itself.
  CHECK_EQ(kHeaderCrcCoverage, sizeof(FrameHeader) - sizeof(uint32_t));
}

TEST(layout_chunk_record_is_48_bytes_unpadded) {
  CHECK_EQ(sizeof(ChunkRecordHeader), size_t{48});
  CHECK_EQ(offsetof(ChunkRecordHeader, fp), size_t{16});
  CHECK_EQ(sizeof(Digest32), size_t{32});
}

TEST(protocol_magic_reads_as_ascii_in_a_hexdump) {
  // Cheap, but it is the thing we will actually rely on at 2am with xxd open.
  char bytes[4];
  std::memcpy(bytes, &kFrameMagic, 4);
  CHECK_EQ(bytes[0], 'W');
  CHECK_EQ(bytes[1], 'R');
  CHECK_EQ(bytes[2], 'P');
  CHECK_EQ(bytes[3], '1');
}

// SPEC 3.6: the queues are "lock-free on the hot path". If std::atomic silently fell
// back to a mutex for any of these widths, that claim would be quietly false -- the
// code would still compile and still be correct, and the headline claim would be a lie.
TEST(atomics_used_by_the_queues_are_lock_free) {
  CHECK(std::atomic<uint32_t>::is_always_lock_free);
  CHECK(std::atomic<uint64_t>::is_always_lock_free);
  CHECK(std::atomic<size_t>::is_always_lock_free);   // Vyukov per-slot sequence counter
  CHECK(std::atomic<void*>::is_always_lock_free);
  CHECK_EQ(alignof(std::atomic<uint64_t>), size_t{8});
}

// SPEC 3.6 pads the SPSC ring's head and tail onto separate cache lines. That padding
// is sized by a constant, so the constant had better match the hardware.
TEST(cache_line_size_is_64_bytes) {
  const long line = ::sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
  std::printf("    note: _SC_LEVEL1_DCACHE_LINESIZE = %ld\n", line);
  if (line > 0) {
    CHECK_EQ(line, 64L);
  } else {
    // Containers on aarch64 frequently report 0 here (the value comes from sysfs,
    // which may not be mounted). Not a failure -- but it means the 64-byte assumption
    // is unverified on this host, which is worth printing rather than hiding.
    std::printf("    note: cache line size unavailable; 64-byte padding assumed\n");
  }
}

// ---------------------------------------------------------------------------
// 3. Socket behaviour -- the facts SPEC S11 is written against
// ---------------------------------------------------------------------------

// THE most important fact in this file. A single send() of N bytes routinely moves
// fewer than N. Every naive `send(fd, buf, len)` in the codebase would be a silent
// truncation bug: the frame is cut in half, the peer reads a header claiming more
// payload than arrives, and the connection wedges. This is why the only permitted way
// to touch a socket is a write_all() loop.
TEST(socket_send_is_short_when_buffers_fill) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p, 4096));
  const int fl = ::fcntl(p.client, F_GETFL, 0);
  REQUIRE(fl >= 0);
  REQUIRE(::fcntl(p.client, F_SETFL, fl | O_NONBLOCK) == 0);

  std::vector<char> buf(4u << 20, 'x');  // 4 MiB, far beyond the 4 KiB buffers
  const ssize_t n = ::send(p.client, buf.data(), buf.size(), MSG_NOSIGNAL);
  std::printf("    note: one send() of %zu bytes moved %zd\n", buf.size(), n);
  CHECK_GT(n, ssize_t{0});
  CHECK_LT(static_cast<size_t>(n), buf.size());
}

// The mirror image: recv() returns what is available, not what you asked for. Every
// frame header read must be a read_exact() loop for the same reason.
TEST(socket_recv_is_partial) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p));
  const char one = 'x';
  REQUIRE(::send(p.server, &one, 1, MSG_NOSIGNAL) == 1);
  char buf[100];
  const ssize_t n = ::recv(p.client, buf, sizeof(buf), 0);
  CHECK_EQ(n, ssize_t{1});  // asked for 100, got 1
}

// Writing to a socket whose peer is gone raises SIGPIPE, whose default disposition is
// to KILL THE PROCESS. A replication daemon that dies when a peer disconnects is not a
// replication daemon. Proven by fork: the child restores the default handler and dies.
TEST(socket_default_sigpipe_kills_an_unprotected_writer) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p));
  ::close(p.server);  // the peer is gone
  p.server = -1;

  const pid_t pid = ::fork();
  REQUIRE(pid >= 0);
  if (pid == 0) {
    ::signal(SIGPIPE, SIG_DFL);  // undo anything the test runner may have set
    const char c = 'x';
    // The first write usually succeeds -- it lands in the send buffer, and only the
    // RST that comes back makes the *next* one fail. Loop, so we observe the real
    // steady-state behaviour rather than a race.
    for (int i = 0; i < 200; i++) {
      const ssize_t r = ::write(p.client, &c, 1);  // plain write(): no MSG_NOSIGNAL
      if (r < 0) ::_exit(2);                       // errno instead of a signal
      ::usleep(5000);
    }
    ::_exit(3);  // never died, never errored
  }
  int status = 0;
  REQUIRE(::waitpid(pid, &status, 0) == pid);
  CHECK(WIFSIGNALED(status));
  if (WIFSIGNALED(status)) {
    CHECK_EQ(WTERMSIG(status), SIGPIPE);
  } else {
    std::printf("    note: child exited normally with code %d (expected a signal)\n",
                WEXITSTATUS(status));
  }
}

// ...and the mitigation. MSG_NOSIGNAL turns that process death into an errno, which is
// a thing we can handle: a dead peer becomes "reconnect and resume" (SPEC 3.7) rather
// than "the daemon is gone".
TEST(socket_msg_nosignal_reports_epipe_instead_of_dying) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p));
  ::close(p.server);
  p.server = -1;

  const char c = 'x';
  bool saw_epipe = false;
  int last_errno = 0;
  for (int i = 0; i < 200 && !saw_epipe; i++) {
    const ssize_t r = ::send(p.client, &c, 1, MSG_NOSIGNAL);
    if (r < 0) {
      last_errno = errno;
      saw_epipe = (errno == EPIPE);
      if (!saw_epipe) break;
    } else {
      ::usleep(5000);
    }
  }
  CHECK(saw_epipe);
  if (!saw_epipe) std::printf("    note: last errno was %d (%s)\n", last_errno,
                              std::strerror(last_errno));
}

// The resume logic (SPEC 3.7) has to tell "the peer finished" from "the peer died",
// and the kernel does distinguish them -- but only if you look. An orderly close is a
// FIN, and recv() reports it as a clean 0.
TEST(socket_orderly_close_reads_zero) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p));
  ::close(p.server);  // FIN: we sent everything we were going to send
  p.server = -1;
  char buf[16];
  const ssize_t n = ::recv(p.client, buf, sizeof(buf), 0);
  CHECK_EQ(n, ssize_t{0});
}

// An abortive close is a RST, and recv() reports ECONNRESET. THIS is what a killed
// node looks like from the other side -- and it is exactly the case the fault matrix
// (SPEC 3.8) injects. Treating it identically to a clean 0 would mean a truncated
// transfer gets committed as if it were complete.
TEST(socket_abortive_close_reports_econnreset) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p));
  linger lg{};
  lg.l_onoff = 1;
  lg.l_linger = 0;  // close() sends RST immediately instead of FIN
  REQUIRE(::setsockopt(p.server, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) == 0);
  ::close(p.server);
  p.server = -1;

  char buf[16];
  const ssize_t n = ::recv(p.client, buf, sizeof(buf), 0);
  const int e = errno;
  CHECK_EQ(n, ssize_t{-1});
  if (n < 0) {
    CHECK_EQ(e, ECONNRESET);
    std::printf("    note: abortive close -> errno %d (%s)\n", e, std::strerror(e));
  } else {
    std::printf("    note: got %zd instead of an error -- RST was not observed\n", n);
  }
}

// A blocking read interrupted by a signal returns EINTR, not data and not an error you
// can give up on. Without an explicit retry, a stray signal (SIGCHLD from a forked
// fault-injection child, a profiler's SIGPROF) turns into a spurious transfer failure.
TEST(blocking_recv_returns_eintr_when_a_signal_arrives) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p));

  struct sigaction sa {};
  sa.sa_handler = on_alarm;
  sa.sa_flags = 0;  // deliberately NOT SA_RESTART -- we want to observe EINTR
  sigemptyset(&sa.sa_mask);
  struct sigaction old {};
  REQUIRE(::sigaction(SIGALRM, &sa, &old) == 0);

  g_alarm_fired = 0;
  itimerval it{};
  it.it_value.tv_usec = 50000;  // 50 ms
  REQUIRE(::setitimer(ITIMER_REAL, &it, nullptr) == 0);

  char buf[16];
  const ssize_t n = ::recv(p.client, buf, sizeof(buf), 0);  // nothing to read: blocks
  const int e = errno;
  ::sigaction(SIGALRM, &old, nullptr);

  CHECK_EQ(n, ssize_t{-1});
  if (n < 0) CHECK_EQ(e, EINTR);
  CHECK(g_alarm_fired != 0);
}

// Baseline for the WAN emulator (SPEC 3.8): every emulated RTT is this number plus
// whatever we add. If the baseline were milliseconds, a 10 ms emulated link would be
// meaningless.
TEST(loopback_round_trip_latency_baseline) {
  TcpPair p;
  REQUIRE(make_tcp_pair(p));
  constexpr int kIters = 500;
  std::vector<double> us;
  us.reserve(kIters);
  char c = 'p';
  for (int i = 0; i < kIters; i++) {
    const auto t0 = std::chrono::steady_clock::now();
    if (::send(p.client, &c, 1, MSG_NOSIGNAL) != 1) break;
    if (::recv(p.server, &c, 1, 0) != 1) break;
    if (::send(p.server, &c, 1, MSG_NOSIGNAL) != 1) break;
    if (::recv(p.client, &c, 1, 0) != 1) break;
    us.push_back(std::chrono::duration<double, std::micro>(
                     std::chrono::steady_clock::now() - t0)
                     .count());
  }
  REQUIRE(us.size() > kIters / 2);
  std::sort(us.begin(), us.end());
  const double p50 = us[us.size() / 2];
  const double p99 = us[us.size() * 99 / 100];
  std::printf("    note: loopback RTT p50 = %.1f us, p99 = %.1f us (%zu samples)\n",
              p50, p99, us.size());
  // Loose bound on purpose: this runs under TSan too, where everything is slower. The
  // number is the deliverable; the assertion only catches a broken environment.
  CHECK_LT(p50, 5000.0);
}

// ---------------------------------------------------------------------------
// 4. Filesystem behaviour -- the facts the commit protocol rests on (SPEC 3.5)
// ---------------------------------------------------------------------------

// The manifest is published by rename(). If rename over an existing file were not
// atomic-or-nothing, a reader could observe a half-written manifest and C1 would fail.
TEST(fs_rename_over_existing_file_replaces_it) {
  TempDir d;
  REQUIRE(!d.path.empty());
  const auto live = d.path / "g0000000001.man";
  const auto tmp = d.path / "g0000000001.man.tmp";
  REQUIRE(write_file(live, "OLD-MANIFEST"));
  REQUIRE(write_file(tmp, "NEW-MANIFEST"));
  REQUIRE(::rename(tmp.c_str(), live.c_str()) == 0);
  CHECK_EQ(read_file(live), std::string("NEW-MANIFEST"));
  CHECK(!std::filesystem::exists(tmp));
}

// rename() makes the new name visible, but the *directory entry* is not durable until
// the directory itself is fsynced. Skipping this is the classic way a file survives
// with the wrong name after a crash.
TEST(fs_directory_fsync_succeeds) {
  TempDir d;
  REQUIRE(!d.path.empty());
  REQUIRE(write_file(d.path / "a", "x"));
  const int dfd = ::open(d.path.c_str(), O_RDONLY | O_DIRECTORY);
  REQUIRE(dfd >= 0);
  const int r = ::fsync(dfd);
  const int e = errno;
  ::close(dfd);
  CHECK_EQ(r, 0);
  if (r != 0) std::printf("    note: fsync(dir) failed: %s\n", std::strerror(e));
}

// SPEC S16: two target processes on one store would interleave appends into the same
// container and corrupt it. flock is the guard, and flock is per open-file-description,
// so two independent open() calls contend even inside one process.
TEST(fs_flock_excludes_a_second_holder) {
  TempDir d;
  REQUIRE(!d.path.empty());
  const auto lock = d.path / "LOCK";
  const int fd1 = ::open(lock.c_str(), O_RDWR | O_CREAT, 0644);
  REQUIRE(fd1 >= 0);
  const int fd2 = ::open(lock.c_str(), O_RDWR | O_CREAT, 0644);
  REQUIRE(fd2 >= 0);
  CHECK_EQ(::flock(fd1, LOCK_EX | LOCK_NB), 0);
  const int second = ::flock(fd2, LOCK_EX | LOCK_NB);
  const int e = errno;
  CHECK_EQ(second, -1);
  if (second == -1) CHECK(e == EWOULDBLOCK || e == EAGAIN);
  ::close(fd2);
  ::close(fd1);
}


// SPEC S16 is enforced by flock -- but T0 discovered a filesystem where flock silently
// does not exclude (CHALLENGES.md B2). These two tests pin down both halves of that
// discovery: the probe reports "exclusive" on a filesystem where locking works, and the
// probe is the thing the target store will consult at open time rather than assuming.
TEST(fs_flock_exclusion_probe_reports_exclusive_on_a_working_filesystem) {
  TempDir d;
  REQUIRE(!d.path.empty());  // TempDir lives on /tmp, which is container-local
  std::string detail;
  const auto s = probe_flock_exclusion(d.path.string(), &detail);
  std::printf("    note: /tmp -> %s (%s)\n", to_string(s), detail.c_str());
  CHECK(s == FlockSupport::kExclusive);
}

// Informational, deliberately non-asserting. It reports the capability of the
// bind-mounted host directory, which is where a user would most naturally put a store
// and where T0 measured exclusion to be broken. It does not assert brokenness: if a
// future Docker Desktop fixes virtiofs, this should start printing "exclusive" and
// nothing should fail. The guard that protects correctness is the probe itself, run at
// store-open time -- not this test.
TEST(fs_report_flock_capability_of_the_bind_mount) {
  const char* candidates[] = {"/work/scratch/out", "/work", "/tmp"};
  for (const char* dir : candidates) {
    struct stat st {};
    if (::stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
    std::string detail;
    const auto s = probe_flock_exclusion(dir, &detail);
    std::printf("    note: %-18s -> %-14s (%s)\n", dir, to_string(s), detail.c_str());
  }
  // The only assertion: the probe must never crash or hang on any of them.
  CHECK(true);
}

// ---------------------------------------------------------------------------
// 5. Timing
// ---------------------------------------------------------------------------

// Every latency number in BENCHMARKS.md comes from steady_clock. If it were not
// steady, an NTP step mid-benchmark would produce a negative duration.
TEST(clock_is_steady_and_fine_grained) {
  CHECK(std::chrono::steady_clock::is_steady);
  // Measure the smallest non-zero delta the clock actually reports.
  double best_ns = 1e18;
  for (int i = 0; i < 1000; i++) {
    const auto a = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point b;
    do {
      b = std::chrono::steady_clock::now();
    } while (b == a);
    best_ns = std::min(
        best_ns, std::chrono::duration<double, std::nano>(b - a).count());
  }
  std::printf("    note: steady_clock granularity ~= %.1f ns\n", best_ns);
  CHECK_LT(best_ns, 10000.0);
}

RUN_ALL()
