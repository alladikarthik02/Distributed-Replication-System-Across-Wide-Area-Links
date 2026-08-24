// Spike: are the T0 filesystem facts true on BOTH filesystems available in the
// container? test_harness measures them on /tmp (overlayfs). The bind-mounted /work
// is virtiofs backed by macOS/APFS, and flock + fsync(dir) are exactly the primitives
// that gateway filesystems get wrong.
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

static void probe(const char* label, const std::string& dir) {
  std::printf("=== %s (%s)\n", label, dir.c_str());
  ::mkdir(dir.c_str(), 0755);

  // 1. rename over an existing file
  const std::string live = dir + "/live", tmp = dir + "/live.tmp";
  int fd = ::open(live.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) { if (::write(fd, "OLD", 3) != 3) std::printf("  write short\n"); ::close(fd); }
  fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) { if (::write(fd, "NEW", 3) != 3) std::printf("  write short\n"); ::close(fd); }
  std::printf("  rename over existing : %s\n",
              ::rename(tmp.c_str(), live.c_str()) == 0 ? "ok" : std::strerror(errno));

  // 2. fsync on the file, then on the directory
  fd = ::open(live.c_str(), O_RDONLY);
  std::printf("  fsync(file)          : %s\n",
              (fd >= 0 && ::fsync(fd) == 0) ? "ok" : std::strerror(errno));
  if (fd >= 0) ::close(fd);
  const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  std::printf("  fsync(dir)           : %s\n",
              (dfd >= 0 && ::fsync(dfd) == 0) ? "ok" : std::strerror(errno));
  if (dfd >= 0) ::close(dfd);

  // 3. flock exclusion across two open file descriptions
  const std::string lk = dir + "/LOCK";
  const int a = ::open(lk.c_str(), O_RDWR | O_CREAT, 0644);
  const int b = ::open(lk.c_str(), O_RDWR | O_CREAT, 0644);
  const int r1 = ::flock(a, LOCK_EX | LOCK_NB);
  const int e1 = errno;
  const int r2 = ::flock(b, LOCK_EX | LOCK_NB);
  const int e2 = errno;
  std::printf("  flock #1             : %s\n", r1 == 0 ? "acquired" : std::strerror(e1));
  std::printf("  flock #2 (must fail) : %s\n",
              r2 == 0 ? "!!! ALSO ACQUIRED -- exclusion is BROKEN" : std::strerror(e2));
  ::close(a); ::close(b);

  // 4. O_DIRECTORY + fdatasync, used by the commit path
  const int d2 = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  std::printf("  fdatasync(dir)       : %s\n",
              (d2 >= 0 && ::fdatasync(d2) == 0) ? "ok" : std::strerror(errno));
  if (d2 >= 0) ::close(d2);
  std::printf("\n");
}

int main() {
  probe("overlayfs  (container-local)", "/tmp/wanrep_spike");
  probe("virtiofs   (bind-mounted from macOS)", "/work/scratch/out/fsprobe");
  return 0;
}
