// Filesystem capability probing.
//
// WHY THIS EXISTS (see CHALLENGES.md B2):
//   SPEC S16 says two processes must never write the same target store, and the
//   enforcement is flock() on <store>/LOCK. That enforcement is only as good as the
//   filesystem underneath it -- and T0 measured a filesystem where it silently is not:
//   on the virtiofs bind mount that Docker Desktop uses to share a macOS directory into
//   the container, two independent open file descriptions BOTH acquire LOCK_EX. No
//   error, no warning, no exclusion. A target store placed there would be corrupted by
//   a second process with no diagnostic at all.
//
//   A comment in the spec would not have helped: the failure is silent and only occurs
//   on a filesystem a user might very reasonably choose. So the check ships. The target
//   store runs this probe at open time and refuses to open where exclusion does not
//   work, which converts a silent corruption into a startup error naming the cause.
#pragma once

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

namespace wanrep {

enum class FlockSupport {
  kExclusive,     // flock() excludes a second holder: safe for a store
  kNotExclusive,  // flock() succeeds twice: S16 CANNOT be enforced here
  kUnavailable,   // could not run the probe (directory missing, no permission, ...)
};

inline const char* to_string(FlockSupport s) {
  switch (s) {
    case FlockSupport::kExclusive: return "exclusive";
    case FlockSupport::kNotExclusive: return "NOT-exclusive";
    case FlockSupport::kUnavailable: return "unavailable";
  }
  return "?";
}

// Probes `dir` by creating a small probe file, opening it twice, and attempting a
// non-blocking exclusive lock on both descriptions. The second attempt MUST fail.
//
// Two independent open() calls are used rather than dup(): flock locks attach to the
// open file description, so a dup'd fd shares the lock and would report success on any
// filesystem, testing nothing. This distinction is the entire reason the probe works
// inside a single process.
inline FlockSupport probe_flock_exclusion(const std::string& dir, std::string* detail = nullptr) {
  const std::string path = dir + "/.wanrep_flock_probe";
  auto note = [&](const char* m) { if (detail) *detail = m; };

  const int a = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
  if (a < 0) {
    if (detail) *detail = std::string("open: ") + ::strerror(errno);
    return FlockSupport::kUnavailable;
  }
  const int b = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
  if (b < 0) {
    if (detail) *detail = std::string("second open: ") + ::strerror(errno);
    ::close(a);
    ::unlink(path.c_str());
    return FlockSupport::kUnavailable;
  }

  FlockSupport result;
  if (::flock(a, LOCK_EX | LOCK_NB) != 0) {
    if (detail) *detail = std::string("first flock: ") + ::strerror(errno);
    result = FlockSupport::kUnavailable;
  } else if (::flock(b, LOCK_EX | LOCK_NB) == 0) {
    note("second flock also succeeded -- no exclusion on this filesystem");
    result = FlockSupport::kNotExclusive;
  } else {
    note("second flock correctly refused");
    result = FlockSupport::kExclusive;
  }

  ::close(b);
  ::close(a);
  ::unlink(path.c_str());
  return result;
}

}  // namespace wanrep
