// The transport interface, and the ONLY sanctioned way to move bytes over one.
//
// SPEC 2.5 measured that a single send() of 4 MiB moved 6 144 bytes, and that a recv()
// asking for 100 bytes returned 1. Those are not edge cases -- they are the normal
// behaviour of a socket under load. So the interface deliberately exposes the truth
// (`write_some` / `read_some` may transfer fewer bytes than asked) and provides exactly
// one correct way to get the whole thing across: the `write_all` / `read_exact` free
// functions below. Production code calls only those. SPEC S11.
//
// `bytes_out()` is load-bearing beyond bookkeeping: EVERY bandwidth number this project
// reports is read from it (SPEC 4.1). It counts bytes actually handed to the transport,
// including all protocol overhead, so the headline reduction figure is a measurement
// rather than a model of what we think we sent.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "wanrep/result.h"
#include "wanrep/types.h"

namespace wanrep {

class Link {
 public:
  virtual ~Link() = default;

  // May transfer FEWER bytes than requested. Returns the count actually transferred,
  // which is always > 0 on success. Never returns 0 with an ok status: a zero-byte
  // read is end-of-stream and is reported as Err::kClosed so it cannot be mistaken for
  // "nothing available right now".
  virtual Result<size_t> write_some(const uint8_t* p, size_t n) = 0;
  virtual Result<size_t> read_some(uint8_t* p, size_t n) = 0;

  virtual void close() = 0;
  virtual bool is_open() const = 0;

  virtual uint64_t bytes_out() const = 0;
  virtual uint64_t bytes_in() const = 0;

  // Human-readable, for error messages and benchmark headers.
  virtual std::string describe() const { return "link"; }
};

// The two functions every caller uses. A short transfer is retried until the buffer is
// exhausted; a genuine error is propagated with its original code intact so kClosed ("the peer
// finished") stays distinguishable from kReset ("the peer died") -- SPEC 3.7 depends on it.
inline Result<void> write_all(Link& link, const uint8_t* p, size_t n) {
  size_t done = 0;
  while (done < n) {
    auto r = link.write_some(p + done, n - done);
    if (!r.ok()) return r.error();
    if (*r == 0) return err(Err::kIo, "write_some returned 0 without an error");
    done += *r;
  }
  return {};
}

inline Result<void> write_all(Link& link, ByteSpan bytes) {
  return write_all(link, bytes.data(), bytes.size());
}

inline Result<void> read_exact(Link& link, uint8_t* p, size_t n) {
  size_t done = 0;
  while (done < n) {
    auto r = link.read_some(p + done, n - done);
    if (!r.ok()) {
      // A clean EOF *partway through* a structure is not a clean EOF -- it is a
      // truncated frame, and calling it kClosed would let a caller treat a half-read
      // header as an orderly shutdown.
      if (r.error().code == Err::kClosed && done > 0) {
        return err(Err::kShortRead, "stream ended mid-structure");
      }
      return r.error();
    }
    if (*r == 0) return err(Err::kIo, "read_some returned 0 without an error");
    done += *r;
  }
  return {};
}

// ---------------------------------------------------------------------------
// MemoryLink -- an in-process transport for tests
// ---------------------------------------------------------------------------
//
// Exists for one reason beyond convenience: `chunk_limit` makes every operation transfer
// at most that many bytes, so write_all/read_exact are exercised against the
// short-transfer behaviour T0 measured on a real socket. A write_all tested only against
// a transport that accepts everything is untested (docs/CHALLENGES.md, T0 open questions).
class MemoryLink : public Link {
 public:
  struct Shared {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<uint8_t> a_to_b;
    std::deque<uint8_t> b_to_a;
    bool a_closed = false;
    bool b_closed = false;
    bool reset = false;  // set by close_abruptly(): peers see kReset, not kClosed
    size_t chunk_limit = 0;
  };

  MemoryLink(std::shared_ptr<Shared> s, bool is_a) : s_(std::move(s)), a_(is_a) {}

  // chunk_limit = 0 means "no artificial limit".
  static std::pair<std::shared_ptr<MemoryLink>, std::shared_ptr<MemoryLink>> make_pair(
      size_t chunk_limit = 0) {
    auto s = std::make_shared<Shared>();
    s->chunk_limit = chunk_limit;
    return {std::make_shared<MemoryLink>(s, true), std::make_shared<MemoryLink>(s, false)};
  }

  Result<size_t> write_some(const uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    std::lock_guard<std::mutex> g(s_->mu);
    if (closed_locked() || peer_closed_locked()) {
      return err(s_->reset ? Err::kReset : Err::kClosed, "write to a closed link");
    }
    const size_t k = s_->chunk_limit ? std::min(n, s_->chunk_limit) : n;
    auto& q = a_ ? s_->a_to_b : s_->b_to_a;
    q.insert(q.end(), p, p + k);
    out_ += k;
    s_->cv.notify_all();
    return k;
  }

  Result<size_t> read_some(uint8_t* p, size_t n) override {
    if (n == 0) return size_t{0};
    std::unique_lock<std::mutex> g(s_->mu);
    auto& q = a_ ? s_->b_to_a : s_->a_to_b;
    s_->cv.wait(g, [&] { return !q.empty() || closed_locked() || peer_closed_locked(); });
    if (q.empty()) {
      if (s_->reset) return err(Err::kReset, "peer aborted");
      return err(Err::kClosed, "peer finished");
    }
    const size_t want = s_->chunk_limit ? std::min(n, s_->chunk_limit) : n;
    const size_t k = std::min(want, q.size());
    for (size_t i = 0; i < k; i++) p[i] = q[i];
    q.erase(q.begin(), q.begin() + static_cast<long>(k));
    in_ += k;
    return k;
  }

  void close() override {
    std::lock_guard<std::mutex> g(s_->mu);
    (a_ ? s_->a_closed : s_->b_closed) = true;
    s_->cv.notify_all();
  }

  // The RST case: the peer must see kReset, not a clean kClosed. This is what a killed
  // node looks like from the other side (SPEC 2.5), and the fault matrix injects it.
  void close_abruptly() {
    std::lock_guard<std::mutex> g(s_->mu);
    s_->reset = true;
    (a_ ? s_->a_closed : s_->b_closed) = true;
    auto& q = a_ ? s_->a_to_b : s_->b_to_a;
    q.clear();  // an RST discards buffered data, exactly like the kernel does
    s_->cv.notify_all();
  }

  bool is_open() const override {
    std::lock_guard<std::mutex> g(s_->mu);
    return !closed_locked() && !peer_closed_locked();
  }

  uint64_t bytes_out() const override { return out_; }
  uint64_t bytes_in() const override { return in_; }
  std::string describe() const override { return a_ ? "memory[a]" : "memory[b]"; }

 private:
  bool closed_locked() const { return a_ ? s_->a_closed : s_->b_closed; }
  bool peer_closed_locked() const { return a_ ? s_->b_closed : s_->a_closed; }

  std::shared_ptr<Shared> s_;
  bool a_;
  uint64_t out_ = 0;
  uint64_t in_ = 0;
};

}  // namespace wanrep
