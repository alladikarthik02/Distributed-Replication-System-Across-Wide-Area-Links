// faultrunner -- kills a real target PROCESS mid-transfer and checks the target is still
// correct afterwards (SPEC 3.8, R3.3, R3.5, S3).
//
// WHY THIS IS A SEPARATE TOOL AND NOT A TEST:
//   The interesting failure is a process dying with NO cleanup -- no destructors, no
//   flush, no FIN, no chance to write a "sorry" record. That cannot be done inside the
//   test runner without killing the test runner. So the target is forked into a real
//   child process, and it is either SIGKILLed from outside or made to _exit(137) from
//   inside at a named injection point.
//
//   The distinction matters: an externally-delivered SIGKILL can land between ANY two
//   instructions, while an injected _exit lands at a point we chose. The first is
//   realistic, the second is reproducible. This runs both.
//
// Usage:
//   faultrunner --list
//   faultrunner [--case <name>] [--seed <n>] [--iterations <n>] [--keep]
//
// Every case ends with the SAME oracle used by every other failure test (R3.4): the store
// verifies clean, visible generations are a prefix, and each committed generation
// materializes byte-identically to the source tree.
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "wanrep/protocol.h"
#include "wanrep/tcp_link.h"

using namespace wanrep;

namespace {

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 0x2545F4914F6CDD1Dull) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
};

bool shell(const std::string& cmd) { return std::system(cmd.c_str()) == 0; }

std::vector<uint8_t> random_blob(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(rng.next() >> 24);
  return v;
}

bool put_file(const std::string& path, const std::vector<uint8_t>& data) {
  return make_dirs(dirname_of(path)).ok() &&
         write_file_atomic(path, ByteSpan(data.data(), data.size())).ok();
}

// How the child dies.
enum class KillMode {
  kInjectedExit,   // _exit(137) from inside, at a named point: reproducible
  kExternalSignal, // SIGKILL from the parent after N bytes: realistic
};

struct Case {
  const char* name;
  KillMode mode;
  FaultPoint point;      // for kInjectedExit
  double kill_fraction;  // for kExternalSignal: fraction of the expected transfer
};

const Case kCases[] = {
    {"kill_after_chunk_fsync", KillMode::kInjectedExit,
     FaultPoint::kAfterChunkFsyncBeforeManifest, 0},
    {"kill_after_manifest_fsync_before_commit", KillMode::kInjectedExit,
     FaultPoint::kAfterManifestFsyncBeforeCommit, 0},
    {"kill_after_commit_before_ack", KillMode::kInjectedExit,
     FaultPoint::kAfterCommitBeforeAck, 0},
    {"sigkill_early_payload", KillMode::kExternalSignal, FaultPoint::kNone, 0.15},
    {"sigkill_mid_payload", KillMode::kExternalSignal, FaultPoint::kNone, 0.50},
    {"sigkill_late_payload", KillMode::kExternalSignal, FaultPoint::kNone, 0.85},
};

// The child: owns the store, serves one connection, then exits. Never returns.
[[noreturn]] void run_target_child(const std::string& store_dir, uint16_t port,
                                   const Case& c) {
  if (c.mode == KillMode::kInjectedExit) {
    global_faults().clear();
    global_faults().arm(c.point, FaultKind::kKillSelf);
  }
  auto store = TargetStore::open(store_dir);
  if (!store.ok()) {
    std::fprintf(stderr, "child: store open failed: %s\n", store.error().message().c_str());
    ::_exit(2);
  }
  auto sessions = SessionJournal::open(store_dir);
  if (!sessions.ok()) ::_exit(3);
  auto listener = TcpLink::Listener::bind("127.0.0.1", port);
  if (!listener.ok()) ::_exit(4);
  auto conn = listener->accept();
  if (!conn.ok()) ::_exit(0);
  TargetServer server(**store, **sessions);
  (void)server.serve(**conn);
  ::_exit(0);
}

// Forks a target child and waits until its port is accepting.
pid_t spawn_target(const std::string& store_dir, uint16_t port, const Case& c) {
  const pid_t pid = ::fork();
  if (pid == 0) run_target_child(store_dir, port, c);
  return pid;
}

bool connect_with_retry(uint16_t port, std::shared_ptr<TcpLink>& out, int tries = 200) {
  for (int i = 0; i < tries; i++) {
    auto l = TcpLink::connect("127.0.0.1", port);
    if (l.ok()) {
      out = *l;
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

struct Outcome {
  bool child_died_uncleanly = false;
  int child_status = 0;
  bool completed = false;
  bool oracle_ok = false;
  std::string detail;
  uint64_t wire_bytes = 0;
};

// The oracle. Identical for every case, run by the PARENT after the child is gone (the
// child holds the store's flock while it lives -- SPEC S16).
bool verify_target(const std::string& store_dir, const std::string& tree,
                   bool expect_committed, std::string& detail) {
  auto store = TargetStore::open(store_dir);
  if (!store.ok()) {
    detail = "reopen failed: " + store.error().message();
    return false;
  }
  auto v = (*store)->verify(true);
  if (!v.ok() || v->problems != 0) {
    detail = "verify reported " + std::to_string(v.ok() ? v->problems : 0) + " problems";
    if (v.ok() && !v->detail.empty()) detail += ": " + v->detail.front();
    return false;
  }
  if (!(*store)->generations().is_prefix_consistent("ds")) {
    detail = "visible generations are not a prefix (C1 violated)";
    return false;
  }
  const bool committed = (*store)->generations().is_committed("ds", 0);
  if (expect_committed && !committed) {
    detail = "expected a committed generation, found none";
    return false;
  }
  if (!committed) {
    detail = "consistent, uncommitted";
    return true;
  }
  auto mb = (*store)->generations().manifest_bytes("ds", 0);
  if (!mb.ok()) {
    detail = "committed manifest unreadable";
    return false;
  }
  auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
  if (!m.ok()) {
    detail = "committed manifest undecodable";
    return false;
  }
  const std::string out = store_dir + "/materialized";
  (void)shell("rm -rf " + out);
  if (!materialize(*m, (*store)->chunks(), out).ok()) {
    detail = "materialize failed";
    return false;
  }
  if (!shell("diff -r " + tree + " " + out + " >/dev/null")) {
    detail = "MATERIALIZED TREE DIFFERS FROM SOURCE";
    return false;
  }
  detail = "committed and byte-identical";
  return true;
}

Outcome run_case(const Case& c, const std::string& tree, const std::string& store_dir,
                 uint16_t port, uint64_t expected_bytes) {
  Outcome o;
  (void)shell("rm -rf " + store_dir);
  if (!make_dirs(store_dir).ok()) return o;

  // --- attempt 1: the child dies partway through ---
  const pid_t child = spawn_target(store_dir, port, c);
  if (child < 0) return o;

  std::shared_ptr<TcpLink> link;
  if (!connect_with_retry(port, link)) {
    ::kill(child, SIGKILL);
    (void)::waitpid(child, nullptr, 0);
    o.detail = "could not connect to the target";
    return o;
  }

  std::atomic<bool> done{false};
  std::thread killer;
  if (c.mode == KillMode::kExternalSignal) {
    // Kill by BYTE COUNT, not by elapsed time: an offset is reproducible from a seed and
    // a moment in time is not (SPEC S15).
    const uint64_t threshold =
        static_cast<uint64_t>(static_cast<double>(expected_bytes) * c.kill_fraction);
    killer = std::thread([&, threshold] {
      while (!done.load(std::memory_order_acquire)) {
        if (link->bytes_out() >= threshold) {
          ::kill(child, SIGKILL);
          return;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
      }
    });
  }

  SourceJob::Options opt;
  opt.dataset = "ds";
  opt.generation = 0;
  std::string session_id;
  auto r = SourceJob::run(*link, tree, opt, nullptr, &session_id);
  done.store(true, std::memory_order_release);
  if (killer.joinable()) killer.join();
  o.wire_bytes += link->bytes_out();
  link->close();

  int status = 0;
  (void)::waitpid(child, &status, 0);
  o.child_status = status;
  o.child_died_uncleanly =
      (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) ||
      (WIFEXITED(status) && WEXITSTATUS(status) == 137);

  // kAfterCommitBeforeAck is the one point where the generation IS durable even though
  // the source never heard back.
  const bool may_be_committed = (c.point == FaultPoint::kAfterCommitBeforeAck);

  // --- attempt 2+: restart the target and finish the job ---
  Case clean = c;
  clean.mode = KillMode::kInjectedExit;
  clean.point = FaultPoint::kNone;
  for (int attempt = 0; attempt < 5 && !o.completed; attempt++) {
    const pid_t child2 = spawn_target(store_dir, static_cast<uint16_t>(port + 1 + attempt), clean);
    if (child2 < 0) break;
    std::shared_ptr<TcpLink> link2;
    if (!connect_with_retry(static_cast<uint16_t>(port + 1 + attempt), link2)) {
      ::kill(child2, SIGKILL);
      (void)::waitpid(child2, nullptr, 0);
      continue;
    }
    SourceJob::Options opt2;
    opt2.dataset = "ds";
    opt2.generation = 0;
    opt2.resume_session_id = session_id;
    auto r2 = SourceJob::run(*link2, tree, opt2, nullptr, &session_id);
    if (!r2.ok() && r2.error().code == Err::kNotFound) session_id.clear();
    o.completed = r2.ok();
    o.wire_bytes += link2->bytes_out();
    link2->close();
    (void)::waitpid(child2, nullptr, 0);
  }
  (void)r;

  o.oracle_ok = verify_target(store_dir, tree, o.completed || may_be_committed, o.detail);
  return o;
}

}  // namespace

int main(int argc, char** argv) {
  std::string only;
  uint64_t seed = 0x9E3779B97F4A7C15ull;
  int iterations = 1;
  bool keep = false;
  for (int i = 1; i < argc; i++) {
    const std::string a = argv[i];
    if (a == "--list") {
      for (const auto& c : kCases) std::printf("%s\n", c.name);
      return 0;
    }
    if (a == "--case" && i + 1 < argc) only = argv[++i];
    else if (a == "--seed" && i + 1 < argc) seed = std::strtoull(argv[++i], nullptr, 0);
    else if (a == "--iterations" && i + 1 < argc) iterations = std::atoi(argv[++i]);
    else if (a == "--keep") keep = true;
    else if (a == "--help") {
      std::printf("usage: faultrunner [--list] [--case <name>] [--seed <n>] "
                  "[--iterations <n>] [--keep]\n");
      return 0;
    }
  }

  const std::string base = "/tmp/wanrep_faultrunner_" + std::to_string(::getpid());
  const std::string tree = base + "/tree";
  if (!make_dirs(tree).ok()) {
    std::fprintf(stderr, "cannot create %s\n", tree.c_str());
    return 1;
  }
  // Several files, sized so a transfer spans many batches and a kill can land anywhere.
  if (!put_file(tree + "/a.bin", random_blob(1200000, seed)) ||
      !put_file(tree + "/b/c.bin", random_blob(700000, seed + 1)) ||
      !put_file(tree + "/b/d.bin", random_blob(400000, seed + 2))) {
    std::fprintf(stderr, "cannot build the source tree\n");
    return 1;
  }

  // A clean baseline, so the SIGKILL cases can aim at a fraction of a real transfer.
  uint64_t expected = 2400000;
  {
    const std::string sd = base + "/baseline";
    const uint16_t port = 45000;
    Case none{"baseline", KillMode::kInjectedExit, FaultPoint::kNone, 0};
    if (make_dirs(sd).ok()) {
      const pid_t pid = spawn_target(sd, port, none);
      std::shared_ptr<TcpLink> l;
      if (pid > 0 && connect_with_retry(port, l)) {
        SourceJob::Options opt;
        opt.dataset = "ds";
        auto r = SourceJob::run(*l, tree, opt);
        if (r.ok()) expected = r->wire_bytes_out;
        l->close();
      }
      (void)::waitpid(pid, nullptr, 0);
    }
  }
  std::printf("wanrep faultrunner -- seed 0x%llx, baseline transfer %llu bytes\n\n",
              static_cast<unsigned long long>(seed),
              static_cast<unsigned long long>(expected));
  std::printf("%-42s %-10s %-9s %-9s %s\n", "case", "child", "completed", "oracle", "detail");
  std::printf("%s\n", std::string(104, '-').c_str());

  int failures = 0, ran = 0;
  uint16_t port = 45100;
  for (int iter = 0; iter < iterations; iter++) {
    for (const auto& c : kCases) {
      if (!only.empty() && only != c.name) continue;
      const std::string sd = base + "/store_" + c.name + "_" + std::to_string(iter);
      const Outcome o = run_case(c, tree, sd, port, expected);
      port = static_cast<uint16_t>(port + 16);
      ran++;
      const bool ok = o.oracle_ok;
      if (!ok) failures++;
      std::printf("%-42s %-10s %-9s %-9s %s\n", c.name,
                  o.child_died_uncleanly ? "killed" : "exited",
                  o.completed ? "yes" : "no", ok ? "PASS" : "FAIL", o.detail.c_str());
      (void)shell("rm -rf " + sd);
    }
  }

  std::printf("\n%d cases run, %d failed\n", ran, failures);
  if (!keep) (void)shell("rm -rf " + base);
  else std::printf("kept: %s\n", base.c_str());
  return failures == 0 ? 0 : 1;
}
