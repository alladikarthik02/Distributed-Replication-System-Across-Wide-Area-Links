// A real TCP socket behind the `Link` interface -- the transport that actually ships.
//
// WHY THIS FILE IS MOSTLY ERROR HANDLING:
//   There are four lines of "move bytes" here and about two hundred lines of "and this
//   is what it means when that fails". That ratio is the point. T0 measured (SPEC 2.5)
//   that every one of send/recv/close has a failure mode that LOOKS LIKE SUCCESS:
//     * send(4 MiB) moved 6 144 bytes and returned a positive number  -> silent truncation
//     * recv(100) with 1 byte available returned 1                    -> silent short read
//     * writing to a dead peer raised SIGPIPE and KILLED THE PROCESS  -> silent death
//     * a peer that died (RST) and a peer that finished (FIN) look identical to code
//       that only checks "did I get an error"
//   Each of those is handled here exactly once, so the rest of the codebase never has to
//   remember. SPEC S11.
//
// THE FOUR RULES THIS CLASS EXISTS TO ENFORCE:
//   1. ALWAYS MSG_NOSIGNAL. Default SIGPIPE disposition is process death, and T0 proved
//      it by forking a child that died with signal 13. A replication daemon that dies
//      when a peer disconnects is not a replication daemon -- it is a way to lose a
//      transfer. With MSG_NOSIGNAL the same event is an EPIPE we can reconnect from,
//      which is what makes SPEC 3.7's resume possible at all.
//   2. EINTR IS RETRIED, on send and on recv. T0 measured that a blocking recv
//      interrupted by a signal returns -1/EINTR. The fault-injection harness forks real
//      child processes (SPEC R3.3), so SIGCHLD is a live hazard on every node; an
//      unretried EINTR would make the test harness manufacture the exact failures it
//      exists to detect.
//   3. kClosed AND kReset STAY DISTINGUISHABLE. recv()==0 is "the peer finished";
//      ECONNRESET (and EPIPE on the write side) is "the peer DIED". SPEC 3.7's resume
//      logic branches on the difference, and collapsing them would let a truncated
//      transfer be committed as complete (SPEC 2.5, S5).
//   4. write_some/read_some REPORT WHAT THE KERNEL ACTUALLY MOVED and never loop
//      internally. link.h's write_all/read_exact are the only loops, so that their
//      correctness is a thing under test rather than a thing duplicated per transport.
//
// WHY TCP_NODELAY:
//   This protocol interleaves small control frames (HELLO, NEED, CHECKPOINT, COMMIT_ACK
//   -- SPEC 3.2) with bulk payload. Nagle's algorithm holds a small write until the
//   previous segment is acknowledged, which on a WAN means up to one RTT of extra delay
//   per control frame, and up to ~40 ms extra when it interacts with delayed ACK. SPEC
//   3.2 already argues that round trips, not bytes, are the WAN enemy; leaving Nagle on
//   would add an invisible round trip to the frames that cost the most.
//
// WHY getaddrinfo AND NOT inet_pton:
//   Tests use "127.0.0.1", but the CLI takes --peer <host:port> from a human. Resolving
//   through getaddrinfo means a hostname works, and AF_UNSPEC means an IPv6-only peer
//   works, without this file growing a second address path later.
//
// REJECTED: non-blocking sockets + an event loop. This project's concurrency design
//   (SPEC 3.6) gives the socket to exactly ONE sender thread and one reader thread, so
//   there is no multiplexing to do; a reactor would add a state machine whose bugs would
//   be indistinguishable from protocol bugs. Blocking I/O with an optional SO_RCVTIMEO
//   backstop is the smaller correct thing.
//
// THREADING CONTRACT -- stated because SPEC 3.6 puts TWO threads on one of these:
//   * write_some() on one thread CONCURRENTLY WITH read_some() on another is supported.
//     They touch opposite queues in the kernel, and the members they touch here (`out_`,
//     `in_`, `fd_`) are atomics for that reason. They are atomics rather than plain
//     integers because SPEC 4.1 makes bytes_out() the authoritative wire-byte counter
//     behind every bandwidth claim in this project, which means something WILL read it
//     while a transfer is running -- a progress meter, bench/rtt_curve. TSan called that
//     a data race when the counters were plain `uint64_t`, and it was right.
//   * close() / close_abruptly() CONCURRENTLY WITH an operation on another thread is NOT
//     safe, and no amount of care inside this class can make it so. Releasing a
//     descriptor hands its NUMBER back to the kernel, which may give it to another
//     thread's open() before the first thread's send() has returned -- so the bytes would
//     go somewhere else entirely. The window is narrowed here (fd_ is exchanged to -1
//     BEFORE the descriptor is released, so an operation that has not yet entered its
//     syscall fails cleanly instead of racing) but it cannot be closed: the thread that is
//     already blocked inside recv() cannot be told to leave without either sending the
//     peer a FIN -- which would turn the abortive close this exists for into the orderly
//     one it must never be -- or waiting on it, which is what it is blocked from doing.
//     FaultLink's byte-triggered drop is precisely this case, so it is documented there
//     as well.
#pragma once

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "wanrep/link.h"
#include "wanrep/result.h"

#if !defined(MSG_NOSIGNAL)
#error "MSG_NOSIGNAL is required: without it a dead peer kills the process (SPEC 2.5)."
#endif

namespace wanrep {

namespace tcp_detail {

// errno -> Err, with the two distinctions SPEC 3.7 depends on preserved.
//
// EPIPE only ever appears on the write side and only because MSG_NOSIGNAL turned the
// fatal signal into an errno; it means the same thing ECONNRESET does -- the peer is
// gone and did not say goodbye -- so both map to kReset.
inline Error map_io_errno(const char* what, bool writing) {
  const int e = errno;
  const std::string ctx = std::string(what);
  if (e == ECONNRESET || (writing && e == EPIPE) || e == ENOTCONN || e == ECONNABORTED) {
    return Error{Err::kReset, ctx + ": peer died", e};
  }
  if (e == EAGAIN || e == EWOULDBLOCK || e == ETIMEDOUT) {
    return Error{Err::kTimeout, ctx + ": timed out", e};
  }
  return Error{Err::kIo, ctx, e};
}

inline Result<void> set_int_opt(int fd, int level, int name, int value, const char* what) {
  if (::setsockopt(fd, level, name, &value, sizeof(value)) != 0) {
    return err_errno(Err::kIo, what);
  }
  return {};
}

// SO_RCVTIMEO/SO_SNDTIMEO. A production node wants a backstop so a peer that goes silent
// without sending a FIN or an RST (a severed cable, a hung VM) becomes an error instead
// of a thread parked forever; tests want it so a bug is a red line rather than a hung CI.
// 0 means "no timeout", which is the default because a *correct* peer can legitimately
// take an unbounded time to answer over a slow WAN.
inline Result<void> set_timeouts(int fd, int ms) {
  if (ms <= 0) return {};
  timeval tv{};
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
    return err_errno(Err::kIo, "SO_RCVTIMEO");
  }
  if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
    return err_errno(Err::kIo, "SO_SNDTIMEO");
  }
  return {};
}

inline Result<uint16_t> socket_port(int fd) {
  sockaddr_storage ss{};
  socklen_t len = sizeof(ss);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) {
    return err_errno(Err::kIo, "getsockname");
  }
  if (ss.ss_family == AF_INET) {
    return static_cast<uint16_t>(ntohs(reinterpret_cast<const sockaddr_in*>(&ss)->sin_port));
  }
  if (ss.ss_family == AF_INET6) {
    return static_cast<uint16_t>(ntohs(reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_port));
  }
  return err(Err::kUnsupported, "socket is not AF_INET/AF_INET6");
}

// Best effort, for describe() only: a failure here must never fail a connection.
inline std::string peer_string(int fd) {
  sockaddr_storage ss{};
  socklen_t len = sizeof(ss);
  if (::getpeername(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return "?";
  char host[NI_MAXHOST], serv[NI_MAXSERV];
  if (::getnameinfo(reinterpret_cast<const sockaddr*>(&ss), len, host, sizeof(host), serv,
                    sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return "?";
  }
  return std::string(host) + ":" + serv;
}

// connect() interrupted by a signal is the one EINTR that must NOT be retried by simply
// calling again: POSIX says the connection attempt continues asynchronously, so a second
// connect() returns EALREADY (or EISCONN) and a naive retry loop would report a spurious
// failure on a connection that actually succeeded. The correct recovery is to wait for
// the socket to become writable and then read the real outcome out of SO_ERROR.
inline Result<void> connect_blocking(int fd, const sockaddr* sa, socklen_t len) {
  if (::connect(fd, sa, len) == 0) return {};
  if (errno != EINTR) return err_errno(Err::kIo, "connect");
  for (;;) {
    pollfd pf{};
    pf.fd = fd;
    pf.events = POLLOUT;
    const int r = ::poll(&pf, 1, -1);
    if (r < 0) {
      if (errno == EINTR) continue;  // poll's EINTR *is* safely retryable
      return err_errno(Err::kIo, "poll(connect)");
    }
    int soerr = 0;
    socklen_t sl = sizeof(soerr);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0) {
      return err_errno(Err::kIo, "getsockopt(SO_ERROR)");
    }
    if (soerr == 0) return {};
    errno = soerr;
    return err_errno(Err::kIo, "connect");
  }
}

}  // namespace tcp_detail

// Socket knobs that must be applied at specific moments, which is why they are a struct
// passed to connect()/bind() rather than setters called afterwards: SO_SNDBUF/SO_RCVBUF
// only influence the advertised window if they are set BEFORE connect (they participate in
// window-scale negotiation during the handshake), and a listener's buffer sizes are what
// accepted sockets inherit.
//
// At namespace scope, not nested inside TcpLink, for a language reason worth knowing: a
// nested class's default member initializers are not available while the ENCLOSING class
// is still incomplete, so `const Options& opt = {}` on a member of TcpLink fails to
// compile if Options is a member of TcpLink. `TcpLink::Options` is kept as an alias so
// call sites still read the way they should.
struct TcpOptions {
  int send_buffer_bytes = 0;  // 0 = kernel default (which auto-tunes; usually right)
  int recv_buffer_bytes = 0;
  int timeout_ms = 0;         // 0 = block indefinitely
  bool nodelay = true;        // see the file header: Nagle costs a WAN round trip
};

class TcpLink : public Link {
 public:
  using Options = TcpOptions;

  explicit TcpLink(int fd) : fd_(fd), peer_(tcp_detail::peer_string(fd)) {}

  ~TcpLink() override { close(); }

  TcpLink(const TcpLink&) = delete;
  TcpLink& operator=(const TcpLink&) = delete;

  static Result<std::shared_ptr<TcpLink>> connect(const std::string& host, uint16_t port,
                                                  const Options& opt = {}) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string service = std::to_string(port);
    const int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
    if (rc != 0) {
      return err(Err::kInvalidArgument,
                 "getaddrinfo(" + host + "): " + std::string(::gai_strerror(rc)));
    }

    Error last = err(Err::kIo, "no address for " + host);
    int fd = -1;
    for (addrinfo* a = res; a != nullptr; a = a->ai_next) {
      fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
      if (fd < 0) {
        last = err_errno(Err::kIo, "socket");
        continue;
      }
      auto prep = apply_options(fd, opt);
      if (!prep.ok()) {
        last = prep.error();
        ::close(fd);
        fd = -1;
        continue;
      }
      auto c = tcp_detail::connect_blocking(fd, a->ai_addr, a->ai_addrlen);
      if (c.ok()) break;
      last = c.error();
      ::close(fd);
      fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd < 0) return last;
    return std::make_shared<TcpLink>(fd);
  }

  // ---- Link ---------------------------------------------------------------

  // Returns what the kernel ACTUALLY accepted, which T0 measured can be 6 144 bytes out
  // of a 4 MiB request. No internal loop: write_all() in link.h owns that, so the loop
  // is written once and tested once (SPEC S11).
  Result<size_t> write_some(const uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    // One load, used for the whole call: re-reading fd_ inside the loop could see the -1
    // a concurrent close() stored and turn a retry into a confusing EBADF.
    const int fd = fd_.load(std::memory_order_acquire);
    if (fd < 0) return err(Err::kClosed, "write on a closed link");
    for (;;) {
      const ssize_t k = ::send(fd, p, n, MSG_NOSIGNAL);
      if (k > 0) {
        out_.fetch_add(static_cast<uint64_t>(k), std::memory_order_relaxed);
        return static_cast<size_t>(k);
      }
      // send() returning 0 for a non-zero request is not a documented outcome; treating
      // it as success would spin write_all() forever, so it is an error by construction.
      if (k == 0) return err(Err::kIo, "send returned 0 for a non-empty buffer");
      if (errno == EINTR) continue;  // rule 2
      return tcp_detail::map_io_errno("send", /*writing=*/true);
    }
  }

  Result<size_t> read_some(uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    const int fd = fd_.load(std::memory_order_acquire);
    if (fd < 0) return err(Err::kClosed, "read on a closed link");
    for (;;) {
      const ssize_t k = ::recv(fd, p, n, 0);
      if (k > 0) {
        in_.fetch_add(static_cast<uint64_t>(k), std::memory_order_relaxed);
        return static_cast<size_t>(k);
      }
      // recv()==0 is FIN: "the peer finished." This is the one place in the codebase
      // that gets to say kClosed, and it must never be produced for an RST (rule 3).
      if (k == 0) return err(Err::kClosed, "peer finished (FIN)");
      if (errno == EINTR) continue;  // rule 2
      return tcp_detail::map_io_errno("recv", /*writing=*/false);
    }
  }

  // Orderly: sends FIN, so the peer's next read returns 0 and means "finished".
  // close() is NOT retried on EINTR: on Linux the descriptor is released regardless, so
  // a retry would close a number that may already have been reused by another thread --
  // the classic double-close bug, which is far worse than the leak it tries to avoid.
  // The exchange happens BEFORE the descriptor is released, not after: it is the only
  // part of this that can be made safe against a concurrent operation, and it converts
  // "syscall on a number the kernel may have already reassigned" into a clean kClosed for
  // every thread that had not yet entered its syscall. See the threading contract above
  // for the part that remains unsafe.
  void close() override {
    const int fd = fd_.exchange(-1, std::memory_order_acq_rel);
    if (fd >= 0) ::close(fd);
  }

  // Abortive: RST instead of FIN, discarding anything still queued -- which is exactly
  // what the far side of a `kill -9`'d node looks like (SPEC 2.5). The peer's next read
  // fails with ECONNRESET, i.e. kReset, and that is the signal SPEC 3.7 resumes from.
  // FaultLink calls this; production code never should.
  void close_abruptly() {
    // SO_LINGER must be set while we still own the descriptor, and the exchange must
    // happen before the close for the reason given in close() -- so the option goes on
    // first, then the number is taken away from every other thread, then it is released.
    const int fd = fd_.load(std::memory_order_acquire);
    if (fd < 0) return;
    linger lg{};
    lg.l_onoff = 1;
    lg.l_linger = 0;  // "linger for zero seconds" is the documented way to ask for a RST
    (void)::setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    const int taken = fd_.exchange(-1, std::memory_order_acq_rel);
    if (taken >= 0) ::close(taken);
  }

  // Whether WE still hold the socket. It deliberately does not claim the peer is alive:
  // TCP cannot know that without sending something, and a function that pretended
  // otherwise would be the most dangerous kind of comfortable lie.
  bool is_open() const override { return fd_.load(std::memory_order_acquire) >= 0; }

  // Relaxed: these are counters, not flags. Nothing is published through them, so no
  // ordering is needed -- only the guarantee that reading one while it is being written
  // is defined behaviour rather than a race (SPEC 4.1, and see the threading contract).
  uint64_t bytes_out() const override { return out_.load(std::memory_order_relaxed); }
  uint64_t bytes_in() const override { return in_.load(std::memory_order_relaxed); }

  std::string describe() const override {
    return "tcp[" + peer_ + " fd=" + std::to_string(fd_.load(std::memory_order_relaxed)) + "]";
  }

  int fd() const { return fd_.load(std::memory_order_acquire); }

  // ---- Listener -----------------------------------------------------------

  class Listener {
   public:
    Listener() = default;
    ~Listener() { close(); }

    // Movable, not copyable: it owns a descriptor, and two owners would mean a double
    // close. Move is needed because bind() returns one by value inside a Result.
    Listener(Listener&& o) noexcept : fd_(o.fd_), port_(o.port_), opt_(o.opt_) {
      o.fd_ = -1;
    }
    Listener& operator=(Listener&& o) noexcept {
      if (this != &o) {
        close();
        fd_ = o.fd_;
        port_ = o.port_;
        opt_ = o.opt_;
        o.fd_ = -1;
      }
      return *this;
    }
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    // port == 0 asks the kernel for an ephemeral port, and port() then reports which one
    // it gave. Tests MUST use this: a hard-coded port makes a suite that fails when a
    // previous run is in TIME_WAIT or when two agents build the repo at once -- i.e. a
    // flake with an external cause, which is the hardest kind to diagnose.
    static Result<Listener> bind(const std::string& host, uint16_t port,
                                 const Options& opt = {}) {
      addrinfo hints{};
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_PASSIVE;
      addrinfo* res = nullptr;
      const std::string service = std::to_string(port);
      const int rc = ::getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(),
                                   &hints, &res);
      if (rc != 0) {
        return err(Err::kInvalidArgument,
                   "getaddrinfo(" + host + "): " + std::string(::gai_strerror(rc)));
      }

      Error last = err(Err::kIo, "no bindable address for " + host);
      int fd = -1;
      for (addrinfo* a = res; a != nullptr; a = a->ai_next) {
        fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) {
          last = err_errno(Err::kIo, "socket");
          continue;
        }
        // SO_REUSEADDR so a restart is not blocked for 2 MSL by connections still in
        // TIME_WAIT from the previous run. It does NOT permit two live listeners on the
        // same port (that would need SO_REUSEPORT), so it costs no exclusivity.
        auto reuse = tcp_detail::set_int_opt(fd, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
        auto prep = reuse.ok() ? apply_options(fd, opt) : reuse;
        if (!prep.ok()) {
          last = prep.error();
          ::close(fd);
          fd = -1;
          continue;
        }
        if (::bind(fd, a->ai_addr, a->ai_addrlen) != 0) {
          last = err_errno(Err::kIo, "bind");
          ::close(fd);
          fd = -1;
          continue;
        }
        // Backlog 16: enough that a client's blocking connect() completes before anyone
        // calls accept(), which is what lets a test set up a pair without a thread.
        if (::listen(fd, 16) != 0) {
          last = err_errno(Err::kIo, "listen");
          ::close(fd);
          fd = -1;
          continue;
        }
        break;
      }
      ::freeaddrinfo(res);
      if (fd < 0) return last;

      auto actual = tcp_detail::socket_port(fd);
      if (!actual.ok()) {
        ::close(fd);
        return actual.error();
      }
      Listener l;
      l.fd_ = fd;
      l.port_ = *actual;
      l.opt_ = opt;
      return l;  // moved, not copied: the descriptor has exactly one owner
    }

    uint16_t port() const { return port_; }
    int fd() const { return fd_; }

    Result<std::shared_ptr<TcpLink>> accept() {
      if (fd_ < 0) return err(Err::kClosed, "accept on a closed listener");
      for (;;) {
        const int c = ::accept(fd_, nullptr, nullptr);
        if (c >= 0) {
          // TCP_NODELAY and the buffer sizes are inherited from the listener on Linux,
          // but that is a kernel implementation detail rather than a POSIX guarantee, so
          // the accepted socket is configured explicitly. Costs two syscalls per
          // connection and removes an assumption.
          auto prep = apply_options(c, opt_);
          if (!prep.ok()) {
            ::close(c);
            return prep.error();
          }
          return std::make_shared<TcpLink>(c);
        }
        if (errno == EINTR) continue;  // rule 2 -- accept's EINTR is safely retryable
        if (errno == ECONNABORTED) continue;  // the client vanished mid-handshake; not our failure
        return tcp_detail::map_io_errno("accept", /*writing=*/false);
      }
    }

    void close() {
      if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
      }
    }

   private:
    int fd_ = -1;
    uint16_t port_ = 0;
    Options opt_{};
  };

 private:
  static Result<void> apply_options(int fd, const Options& opt) {
    if (opt.nodelay) {
      WANREP_TRY(tcp_detail::set_int_opt(fd, IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY"));
    }
    if (opt.send_buffer_bytes > 0) {
      WANREP_TRY(tcp_detail::set_int_opt(fd, SOL_SOCKET, SO_SNDBUF, opt.send_buffer_bytes,
                                         "SO_SNDBUF"));
    }
    if (opt.recv_buffer_bytes > 0) {
      WANREP_TRY(tcp_detail::set_int_opt(fd, SOL_SOCKET, SO_RCVBUF, opt.recv_buffer_bytes,
                                         "SO_RCVBUF"));
    }
    WANREP_TRY(tcp_detail::set_timeouts(fd, opt.timeout_ms));
    return {};
  }

  std::atomic<int> fd_{-1};
  std::string peer_;
  std::atomic<uint64_t> out_{0};
  std::atomic<uint64_t> in_{0};
};

}  // namespace wanrep
