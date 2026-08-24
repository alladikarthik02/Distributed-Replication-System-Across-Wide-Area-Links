// Result<T> and Error -- the return type of every fallible operation.
//
// WHY NOT EXCEPTIONS:
//   Two reasons, and only the second is about taste. (1) The I/O paths here are the hot
//   paths, and an error on them (a short read, a dropped link, a bad CRC) is an ORDINARY
//   event, not an exceptional one -- SPEC 3.7 treats a dropped connection as a normal
//   state transition. (2) SPEC S11 requires that no failure is ever silent, and a
//   [[nodiscard]] Result makes ignoring one a compile error, which is a stronger
//   guarantee than "someone remembered to catch it".
//
// WHY THE ERROR CARRIES A STRING AND AN ERRNO:
//   T0 measured that the same syscall failure means different things depending on errno
//   -- recv() returning 0 is "the peer finished" while ECONNRESET is "the peer DIED"
//   (SPEC 2.5). Collapsing those into one "io error" would destroy the distinction the
//   resume logic in SPEC 3.7 is built on. So the code enum keeps them separate AND the
//   raw errno is preserved for the message.
#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

namespace wanrep {

enum class Err : uint16_t {
  kOk = 0,

  // --- transport -----------------------------------------------------------
  kIo,      // a syscall failed; sys_errno carries which
  kClosed,  // orderly shutdown: recv() returned 0. "The peer finished."
  kReset,   // abortive close: ECONNRESET. "The peer DIED."   <- distinct on purpose
  kTimeout,

  // --- framing / parsing ---------------------------------------------------
  kShortRead,      // the stream ended in the middle of a structure
  kBadMagic,
  kBadHeaderCrc,   // header failed its own CRC -- checked BEFORE any field is used (S7)
  kBadPayloadCrc,
  kTooLarge,       // a declared length exceeded a hard cap, before any allocation (S7)
  kMalformed,      // structurally invalid input
  kUnsupported,    // protocol version or capability mismatch

  // --- store ---------------------------------------------------------------
  kNotFound,
  kExists,
  kCorrupt,               // on-disk bytes failed verification
  kFingerprintMismatch,   // S17: the sender's claimed chunk name is not its content's hash
  kLocked,                // S16: the store is already open elsewhere
  kUnsafeFilesystem,      // S16: flock exclusion is not enforceable here (CHALLENGES B2)

  // --- protocol / control --------------------------------------------------
  kProtocol,       // the peer violated the state machine
  kFaultInjected,  // deliberate, from fault.h -- never produced in production
  kCancelled,
  kInvalidArgument,
};

inline const char* to_string(Err e) {
  switch (e) {
    case Err::kOk: return "ok";
    case Err::kIo: return "io";
    case Err::kClosed: return "closed";
    case Err::kReset: return "reset";
    case Err::kTimeout: return "timeout";
    case Err::kShortRead: return "short-read";
    case Err::kBadMagic: return "bad-magic";
    case Err::kBadHeaderCrc: return "bad-header-crc";
    case Err::kBadPayloadCrc: return "bad-payload-crc";
    case Err::kTooLarge: return "too-large";
    case Err::kMalformed: return "malformed";
    case Err::kUnsupported: return "unsupported";
    case Err::kNotFound: return "not-found";
    case Err::kExists: return "exists";
    case Err::kCorrupt: return "corrupt";
    case Err::kFingerprintMismatch: return "fingerprint-mismatch";
    case Err::kLocked: return "locked";
    case Err::kUnsafeFilesystem: return "unsafe-filesystem";
    case Err::kProtocol: return "protocol";
    case Err::kFaultInjected: return "fault-injected";
    case Err::kCancelled: return "cancelled";
    case Err::kInvalidArgument: return "invalid-argument";
  }
  return "?";
}

struct Error {
  Err code = Err::kOk;
  std::string detail;
  int sys_errno = 0;

  std::string message() const {
    std::string m = to_string(code);
    if (!detail.empty()) m += ": " + detail;
    if (sys_errno != 0) m += " (" + std::string(std::strerror(sys_errno)) + ")";
    return m;
  }
};

// Construction helpers. `err_errno` captures errno at the call site, which is the only
// place it is still valid -- one intervening library call can clobber it.
inline Error err(Err code, std::string detail = {}) {
  return Error{code, std::move(detail), 0};
}
inline Error err_errno(Err code, std::string detail = {}) {
  return Error{code, std::move(detail), errno};
}

template <class T>
class [[nodiscard]] Result {
 public:
  Result(T v) : value_(std::move(v)) {}                     // NOLINT: implicit on purpose
  Result(Error e) : error_(std::move(e)) {}                 // NOLINT
  Result(Err code) : error_(Error{code, {}, 0}) {}          // NOLINT

  bool ok() const { return value_.has_value(); }
  explicit operator bool() const { return ok(); }

  T& operator*() { return *value_; }
  const T& operator*() const { return *value_; }
  T* operator->() { return &*value_; }
  const T* operator->() const { return &*value_; }

  T value_or(T fallback) const { return value_ ? *value_ : std::move(fallback); }
  const Error& error() const { return error_; }
  Err code() const { return value_ ? Err::kOk : error_.code; }

 private:
  std::optional<T> value_;
  Error error_;
};

// void specialization: an operation that can fail but returns nothing.
template <>
class [[nodiscard]] Result<void> {
 public:
  Result() = default;
  Result(Error e) : error_(std::move(e)), ok_(false) {}   // NOLINT
  Result(Err code) : error_(Error{code, {}, 0}), ok_(code == Err::kOk) {}  // NOLINT

  bool ok() const { return ok_; }
  explicit operator bool() const { return ok_; }
  const Error& error() const { return error_; }
  Err code() const { return ok_ ? Err::kOk : error_.code; }

 private:
  Error error_;
  bool ok_ = true;
};

// Propagate an error out of the current function, preserving its detail. Used pervasively
// on I/O paths so that an error surfaces at its origin rather than being flattened into
// a generic failure three layers up.
#define WANREP_TRY(expr)                        \
  do {                                          \
    auto _r = (expr);                           \
    if (!_r.ok()) return _r.error();            \
  } while (0)

// Same, but binds the value.  WANREP_ASSIGN(auto n, link.read_some(p, k));
#define WANREP_ASSIGN(decl, expr)               \
  auto _tmp_##__LINE__ = (expr);                \
  if (!_tmp_##__LINE__.ok()) return _tmp_##__LINE__.error(); \
  decl = std::move(*_tmp_##__LINE__)

}  // namespace wanrep
