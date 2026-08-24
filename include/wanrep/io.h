// Checked file I/O.
//
// WHY THIS EXISTS AT ALL:
//   SPEC S11 says no failure is ever silent. On a socket that means short transfers
//   (T0 measured a 4 MiB send() moving 6 144 bytes); on a file it means short writes,
//   EINTR, and -- the one that actually loses data -- an unchecked fsync(). Every
//   syscall in this project goes through one of the wrappers here, so "did we check the
//   return value?" is answered once, in one file, instead of at 200 call sites.
//
// WHY THE PUBLISH SEQUENCE IS A FUNCTION AND NOT A CONVENTION:
//   SPEC S4 requires that nothing is referenced before it is durable. The ordering
//   tmp -> fsync(file) -> rename -> fsync(dir) is easy to state and easy to get subtly
//   wrong (the last step is the one everyone forgets, and skipping it is how a file
//   survives a crash under the wrong name -- T0 verified fsync-on-a-directory works
//   here precisely so this could rely on it). It is written once, as write_file_atomic().
#pragma once

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include "wanrep/fault.h"
#include "wanrep/result.h"
#include "wanrep/types.h"

namespace wanrep {

// EINTR is not an error, it is an interruption. T0 proved a blocking syscall interrupted
// by a signal returns -1/EINTR, and the fault tests fork children, so SIGCHLD is a live
// hazard here. Retrying is not optional.
//
// A function template rather than the more obvious `({ ... })` statement-expression
// macro: statement expressions are a GNU extension, and CMakeLists.txt sets
// CMAKE_CXX_EXTENSIONS OFF with the comment "portability is a claim we make". Reaching
// for a GNU extension to implement the portability layer would have contradicted the
// project's own stated rule -- and -Wpedantic said so, loudly, at every call site.
template <class Fn>
auto eintr_retry(Fn&& fn) -> decltype(fn()) {
  decltype(fn()) r;
  do {
    r = fn();
  } while (r == -1 && errno == EINTR);
  return r;
}

class File {
 public:
  File() = default;
  ~File() { reset(); }

  File(File&& o) noexcept : fd_(o.fd_), path_(std::move(o.path_)) { o.fd_ = -1; }
  File& operator=(File&& o) noexcept {
    if (this != &o) {
      reset();
      fd_ = o.fd_;
      path_ = std::move(o.path_);
      o.fd_ = -1;
    }
    return *this;
  }
  File(const File&) = delete;
  File& operator=(const File&) = delete;

  static Result<File> open_read(const std::string& path) {
    const int fd = eintr_retry([&] { return ::open(path.c_str(), O_RDONLY | O_CLOEXEC); });
    if (fd < 0) return err_errno(Err::kIo, "open(read) " + path);
    return File(fd, path);
  }

  // Read-write, created if absent. Used for containers and journals, which are appended
  // to and also read back during recovery.
  static Result<File> open_rw(const std::string& path, bool create = true) {
    const int flags = O_RDWR | O_CLOEXEC | (create ? O_CREAT : 0);
    const int fd = eintr_retry([&] { return ::open(path.c_str(), flags, 0644); });
    if (fd < 0) return err_errno(Err::kIo, "open(rw) " + path);
    return File(fd, path);
  }

  static Result<File> create_truncate(const std::string& path) {
    const int fd =
        eintr_retry([&] { return ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644); });
    if (fd < 0) return err_errno(Err::kIo, "create " + path);
    return File(fd, path);
  }

  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  const std::string& path() const { return path_; }

  // Appends at `off`. pwrite does not touch the file offset, so two threads appending to
  // different containers never interfere, and a retry after a short write cannot
  // accidentally re-position.
  Result<void> pwrite_all(ByteSpan bytes, uint64_t off) {
    size_t done = 0;
    while (done < bytes.size()) {
      const ssize_t n = eintr_retry([&] { return ::pwrite(fd_, bytes.data() + done, bytes.size() - done, static_cast<off_t>(off + done)); });
      if (n < 0) return err_errno(Err::kIo, "pwrite " + path_);
      if (n == 0) return err(Err::kIo, "pwrite wrote 0 bytes " + path_);
      done += static_cast<size_t>(n);
    }
    return {};
  }

  Result<void> write_all(ByteSpan bytes) {
    size_t done = 0;
    while (done < bytes.size()) {
      const ssize_t n =
          eintr_retry([&] { return ::write(fd_, bytes.data() + done, bytes.size() - done); });
      if (n < 0) return err_errno(Err::kIo, "write " + path_);
      if (n == 0) return err(Err::kIo, "write wrote 0 bytes " + path_);
      done += static_cast<size_t>(n);
    }
    return {};
  }

  // Reads exactly n bytes at `off`. A short read here means the file is shorter than the
  // caller believed, which for us always means a torn tail -- so it is kShortRead, a
  // distinct and recoverable condition, not a generic I/O failure.
  Result<void> pread_exact(uint8_t* p, size_t n, uint64_t off) {
    size_t done = 0;
    while (done < n) {
      const ssize_t r = eintr_retry([&] { return ::pread(fd_, p + done, n - done, static_cast<off_t>(off + done)); });
      if (r < 0) return err_errno(Err::kIo, "pread " + path_);
      if (r == 0) return err(Err::kShortRead, "pread past end of " + path_);
      done += static_cast<size_t>(r);
    }
    return {};
  }

  Result<uint64_t> size() const {
    struct stat st {};
    if (::fstat(fd_, &st) != 0) return err_errno(Err::kIo, "fstat " + path_);
    return static_cast<uint64_t>(st.st_size);
  }

  Result<void> fsync() {
    // Injection point: a crash here means the data is written but not durable, which is
    // the case S4's ordering exists to survive.
    if (WANREP_FAULT(FaultPoint::kAfterChunkFsyncBeforeManifest) == FaultKind::kIoError) {
      return err(Err::kFaultInjected, "fsync " + path_);
    }
    if (eintr_retry([&] { return ::fsync(fd_); }) != 0) return err_errno(Err::kIo, "fsync " + path_);
    return {};
  }

  Result<void> truncate(uint64_t n) {
    if (eintr_retry([&] { return ::ftruncate(fd_, static_cast<off_t>(n)); }) != 0) {
      return err_errno(Err::kIo, "ftruncate " + path_);
    }
    return {};
  }

  // flock, held for the lifetime of this File. SPEC S16.
  Result<void> lock_exclusive() {
    if (::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        return err(Err::kLocked, "already locked: " + path_);
      }
      return err_errno(Err::kIo, "flock " + path_);
    }
    return {};
  }

  void reset() {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  File(int fd, std::string path) : fd_(fd), path_(std::move(path)) {}
  int fd_ = -1;
  std::string path_;
};

inline Result<void> make_dirs(const std::string& path) {
  // Creates every component. mkdir returning EEXIST is success, not failure -- the
  // distinction matters because ignoring *all* mkdir errors is how a store silently
  // gets built in the wrong place.
  std::string acc;
  size_t i = 0;
  if (!path.empty() && path[0] == '/') {
    acc = "/";
    i = 1;
  }
  while (i <= path.size()) {
    const size_t slash = path.find('/', i);
    const size_t end = (slash == std::string::npos) ? path.size() : slash;
    if (end > i) {
      acc += path.substr(i, end - i);
      if (::mkdir(acc.c_str(), 0755) != 0 && errno != EEXIST) {
        return err_errno(Err::kIo, "mkdir " + acc);
      }
      acc += "/";
    }
    if (slash == std::string::npos) break;
    i = slash + 1;
  }
  return {};
}

// The step everyone forgets. rename() makes the new name visible; only fsync on the
// containing directory makes that name durable. T0 verified this returns 0 on both
// filesystems in the container (SPEC 2.5) precisely so this could depend on it.
inline Result<void> fsync_dir(const std::string& dir) {
  const int fd = eintr_retry([&] { return ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); });
  if (fd < 0) return err_errno(Err::kIo, "open(dir) " + dir);
  const int r = eintr_retry([&] { return ::fsync(fd); });
  const int saved = errno;
  ::close(fd);
  if (r != 0) {
    errno = saved;
    return err_errno(Err::kIo, "fsync(dir) " + dir);
  }
  return {};
}

inline std::string dirname_of(const std::string& path) {
  const size_t slash = path.rfind('/');
  return (slash == std::string::npos) ? std::string(".") : path.substr(0, slash);
}

// The publish sequence of SPEC S4, written once so it cannot be got subtly wrong twice.
//
//   write tmp -> fsync(tmp) -> rename(tmp, final) -> fsync(dir)
//
// After this returns, `path` either holds all of `data` or holds its previous contents.
// It never holds a prefix: that is the entire point, and it is what lets a manifest be
// published without a reader ever observing half of one.
inline Result<void> write_file_atomic(const std::string& path, ByteSpan data) {
  const std::string tmp = path + ".tmp";
  {
    auto f = File::create_truncate(tmp);
    if (!f.ok()) return f.error();
    WANREP_TRY(f->write_all(data));
    WANREP_TRY(f->fsync());
  }
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    return err_errno(Err::kIo, "rename " + tmp + " -> " + path);
  }
  return fsync_dir(dirname_of(path));
}

inline Result<std::vector<uint8_t>> read_whole_file(const std::string& path,
                                                    size_t max_bytes = 1u << 30) {
  auto f = File::open_read(path);
  if (!f.ok()) return f.error();
  auto sz = f->size();
  if (!sz.ok()) return sz.error();
  // Bound the allocation against a stated cap before making it (SPEC S7). A store file
  // is not attacker-controlled the way a frame is, but a corrupt size is still a size.
  if (*sz > max_bytes) return err(Err::kTooLarge, "file too large: " + path);
  std::vector<uint8_t> buf(static_cast<size_t>(*sz));
  if (*sz > 0) WANREP_TRY(f->pread_exact(buf.data(), buf.size(), 0));
  return buf;
}

inline bool path_exists(const std::string& path) {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0;
}

}  // namespace wanrep
