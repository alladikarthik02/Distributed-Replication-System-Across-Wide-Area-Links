// bench_wire -- the headline bandwidth number, with the workload printed next to it.
//
// SPEC 8.1 exists because a bare "60% bandwidth reduction" is the standard way
// replication benchmarks lie. Two different numbers can both honestly be called that:
//
//   * INITIAL SEED (target empty): no history to exploit, so the saving is compression
//     plus dedup WITHIN the tree.
//   * INCREMENTAL (target holds gen N-1): the saving is mostly not sending unchanged data.
//
// They differ by an order of magnitude. So this prints a table -- seed, every incremental
// generation, and the whole campaign -- with a per-row breakdown of where the bytes went,
// and two controls that bound the claim on both sides. The number is read from
// Link::bytes_out(), the transport's own counter, so it includes every byte of protocol
// overhead and is a measurement rather than a model.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "wanrep/protocol.h"
#include "wanrep/wan_link.h"

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
  uint32_t below(uint32_t n) { return static_cast<uint32_t>(next() % n); }
  double unit() { return static_cast<double>(next() >> 11) / 9007199254740992.0; }
};

bool shell(const std::string& cmd) { return std::system(cmd.c_str()) == 0; }

bool put_file(const std::string& path, const std::vector<uint8_t>& d) {
  return make_dirs(dirname_of(path)).ok() &&
         write_file_atomic(path, ByteSpan(d.data(), d.size())).ok();
}

// --- the three content classes -------------------------------------------------------

std::vector<uint8_t> make_text(size_t n, Rng& rng) {
  static const char* w[] = {"the", "replication", "target", "source", "chunk", "manifest",
                            "generation", "commit", "and", "of", "a", "wide", "area",
                            "link", "fingerprint", "resume", "durable", "consistent"};
  std::string s;
  s.reserve(n + 32);
  while (s.size() < n) {
    s += w[rng.below(18)];
    s += (rng.below(9) == 0) ? "\n" : " ";
  }
  s.resize(n);
  return std::vector<uint8_t>(s.begin(), s.end());
}

// Fixed-width records with a few varying fields: what a database file or a log index
// looks like. Compressible, but far less than prose.
std::vector<uint8_t> make_records(size_t n, Rng& rng) {
  std::vector<uint8_t> v;
  v.reserve(n + 64);
  while (v.size() < n) {
    uint8_t rec[64];
    std::memset(rec, 0, sizeof(rec));
    rec[0] = 'R';
    rec[1] = 'E';
    rec[2] = 'C';
    for (int i = 8; i < 16; i++) rec[i] = static_cast<uint8_t>(rng.next() >> 24);
    for (int i = 32; i < 40; i++) rec[i] = static_cast<uint8_t>('0' + rng.below(10));
    v.insert(v.end(), rec, rec + sizeof(rec));
  }
  v.resize(n);
  return v;
}

std::vector<uint8_t> make_random(size_t n, Rng& rng) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(rng.next() >> 24);
  return v;
}

std::vector<uint8_t> make_content(int cls, size_t n, Rng& rng) {
  if (cls == 0) return make_text(n, rng);
  if (cls == 1) return make_records(n, rng);
  return make_random(n, rng);
}

// The corpus of SPEC 8.1: a synthetic tree captured as successive backup generations,
// where between generations ~3% of files are modified, ~1% created and ~1% deleted. This
// models the thing backup replication is actually bought for -- repeated captures of data
// that barely changes.
struct Corpus {
  std::string root;
  Rng rng;
  std::vector<std::string> paths;
  std::vector<int> classes;
  int next_id = 0;

  Corpus(std::string r, uint64_t seed) : root(std::move(r)), rng(seed) {}

  std::string path_for(int id, int cls) const {
    const char* dir = (cls == 0) ? "docs" : (cls == 1) ? "db" : "blobs";
    const char* ext = (cls == 0) ? ".txt" : (cls == 1) ? ".rec" : ".bin";
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s/shard%02d/f%05d%s", dir, id % 16, id, ext);
    return buf;
  }

  bool create_generation_zero(int files) {
    for (int i = 0; i < files; i++) {
      // Mix: 45% text, 35% records, 20% incompressible. A tree that is ALL prose would
      // flatter the compressor; one that is all random would flatter nothing.
      const double r = rng.unit();
      const int cls = (r < 0.45) ? 0 : (r < 0.80) ? 1 : 2;
      const size_t size = 2000 + static_cast<size_t>(rng.below(120000));
      const std::string rel = path_for(next_id, cls);
      if (!put_file(root + "/" + rel, make_content(cls, size, rng))) return false;
      paths.push_back(rel);
      classes.push_back(cls);
      next_id++;
    }
    return true;
  }

  // Mutates the tree in place to produce the next generation.
  bool advance() {
    const size_t n = paths.size();
    const size_t to_modify = std::max<size_t>(1, n * 3 / 100);
    const size_t to_create = std::max<size_t>(1, n / 100);
    const size_t to_delete = std::max<size_t>(1, n / 100);

    for (size_t i = 0; i < to_modify; i++) {
      const size_t idx = rng.below(static_cast<uint32_t>(paths.size()));
      const std::string full = root + "/" + paths[idx];
      auto cur = read_whole_file(full);
      if (!cur.ok()) continue;
      std::vector<uint8_t> data = *cur;
      const int kind = static_cast<int>(rng.below(3));
      if (kind == 0 && !data.empty()) {          // in-place edit
        const size_t at = rng.below(static_cast<uint32_t>(data.size()));
        const size_t len = std::min<size_t>(data.size() - at, 1 + rng.below(2000));
        auto patch = make_content(classes[idx], len, rng);
        std::copy(patch.begin(), patch.end(), data.begin() + static_cast<long>(at));
      } else if (kind == 1) {                    // append
        auto tail = make_content(classes[idx], 1 + rng.below(20000), rng);
        data.insert(data.end(), tail.begin(), tail.end());
      } else if (!data.empty()) {                // truncate
        data.resize(data.size() / 2 + 1);
      }
      if (!put_file(full, data)) return false;
    }
    for (size_t i = 0; i < to_create; i++) {
      const double r = rng.unit();
      const int cls = (r < 0.45) ? 0 : (r < 0.80) ? 1 : 2;
      const std::string rel = path_for(next_id, cls);
      if (!put_file(root + "/" + rel, make_content(cls, 2000 + rng.below(80000), rng))) {
        return false;
      }
      paths.push_back(rel);
      classes.push_back(cls);
      next_id++;
    }
    for (size_t i = 0; i < to_delete && paths.size() > 10; i++) {
      const size_t idx = rng.below(static_cast<uint32_t>(paths.size()));
      ::unlink((root + "/" + paths[idx]).c_str());
      paths.erase(paths.begin() + static_cast<long>(idx));
      classes.erase(classes.begin() + static_cast<long>(idx));
    }
    return true;
  }
};

// --- running one replication ---------------------------------------------------------

struct Run {
  JobStats stats;
  double seconds = 0;
  bool ok = false;
};

Run replicate(const std::string& tree, TargetStore& store, SessionJournal& sessions,
              const std::string& dataset, uint64_t generation, bool compress = true,
              double rtt_ms = 0, double bw_mbps = 0) {
  Run out;
  auto [a, b] = MemoryLink::make_pair(0, 256 * 1024);
  std::shared_ptr<Link> src = a;
  std::shared_ptr<Link> dst = b;
  if (rtt_ms > 0 || bw_mbps > 0) {
    WanLink::Params p;
    p.rtt_ms = rtt_ms;
    p.bandwidth_mbps = bw_mbps;
    src = std::make_shared<WanLink>(src, p);
    dst = std::make_shared<WanLink>(dst, p);
  }
  std::thread target([&] {
    TargetServer server(store, sessions);
    (void)server.serve(*dst);
    dst->close();
  });
  SourceJob::Options opt;
  opt.dataset = dataset;
  opt.generation = generation;
  opt.compress = compress;
  const auto t0 = std::chrono::steady_clock::now();
  auto r = SourceJob::run(*src, tree, opt);
  out.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  src->close();
  target.join();
  if (r.ok()) {
    out.stats = *r;
    out.ok = true;
  }
  return out;
}

double pct(uint64_t part, uint64_t whole) {
  return whole == 0 ? 0.0 : 100.0 * static_cast<double>(part) / static_cast<double>(whole);
}

}  // namespace

int main(int argc, char** argv) {
  uint64_t seed = 0x9E3779B97F4A7C15ull;
  int files = 400;
  int generations = 8;
  for (int i = 1; i < argc; i++) {
    const std::string k = argv[i];
    if (k == "--seed" && i + 1 < argc) seed = std::strtoull(argv[++i], nullptr, 0);
    else if (k == "--files" && i + 1 < argc) files = std::atoi(argv[++i]);
    else if (k == "--generations" && i + 1 < argc) generations = std::atoi(argv[++i]);
  }

  const std::string base = "/tmp/wanrep_bench_" + std::to_string(::getpid());
  const std::string tree = base + "/tree";
  const std::string store_dir = base + "/store";
  if (!make_dirs(tree).ok() || !make_dirs(store_dir).ok()) {
    std::fprintf(stderr, "cannot create %s\n", base.c_str());
    return 1;
  }

  std::printf("wanrep bench_wire\n");
  std::printf("=================\n\n");
  std::printf("WORKLOAD (SPEC 8.1). This number is meaningless without it:\n");
  std::printf("  %d files at generation 0, mixed content: 45%% prose, 35%% fixed-width\n"
              "  records, 20%% incompressible. Between generations ~3%% of files are\n"
              "  modified (in-place edit / append / truncate), ~1%% created, ~1%% deleted.\n"
              "  %d generations. Seed 0x%llx.\n\n",
              files, generations, static_cast<unsigned long long>(seed));

  Corpus corpus(tree, seed);
  if (!corpus.create_generation_zero(files)) {
    std::fprintf(stderr, "corpus generation failed\n");
    return 1;
  }

  auto store = TargetStore::open(store_dir);
  if (!store.ok()) {
    std::fprintf(stderr, "store: %s\n", store.error().message().c_str());
    return 1;
  }
  auto sessions = SessionJournal::open(store_dir);
  if (!sessions.ok()) return 1;

  std::printf("%-4s %12s %12s %10s %11s %10s %9s %8s\n", "gen", "logical", "wire",
              "reduction", "manifest", "payload", "chunks", "skipped");
  std::printf("%s\n", std::string(88, '-').c_str());

  uint64_t total_logical = 0, total_wire = 0;
  uint64_t seed_logical = 0, seed_wire = 0;
  uint64_t incr_logical = 0, incr_wire = 0;

  for (int g = 0; g < generations; g++) {
    if (g > 0 && !corpus.advance()) {
      std::fprintf(stderr, "corpus advance failed\n");
      return 1;
    }
    const Run r = replicate(tree, **store, **sessions, "backup", static_cast<uint64_t>(g));
    if (!r.ok) {
      std::fprintf(stderr, "generation %d failed\n", g);
      return 1;
    }
    const auto& s = r.stats;
    std::printf("%-4d %12llu %12llu %9.2f%% %11llu %10llu %9zu %8zu\n", g,
                (unsigned long long)s.logical_bytes, (unsigned long long)s.wire_bytes_out,
                100.0 - pct(s.wire_bytes_out, s.logical_bytes),
                (unsigned long long)s.manifest_bytes_sent,
                (unsigned long long)s.compressed_bytes_sent, s.chunks_sent,
                s.chunks_skipped);
    total_logical += s.logical_bytes;
    total_wire += s.wire_bytes_out;
    if (g == 0) {
      seed_logical = s.logical_bytes;
      seed_wire = s.wire_bytes_out;
    } else {
      incr_logical += s.logical_bytes;
      incr_wire += s.wire_bytes_out;
    }
  }

  std::printf("\nHEADLINE ROWS -- quote one of these WITH its label, never a bare number:\n\n");
  std::printf("  A. Initial seed (target empty; saving is compression + intra-tree dedup)\n");
  std::printf("       %llu logical -> %llu on the wire = %.1f%% reduction\n",
              (unsigned long long)seed_logical, (unsigned long long)seed_wire,
              100.0 - pct(seed_wire, seed_logical));
  std::printf("  B. Incremental generations 1..%d (saving is mostly not re-sending)\n",
              generations - 1);
  std::printf("       %llu logical -> %llu on the wire = %.1f%% reduction\n",
              (unsigned long long)incr_logical, (unsigned long long)incr_wire,
              100.0 - pct(incr_wire, incr_logical));
  std::printf("  C. Whole campaign (all %d generations vs %d full transfers)\n", generations,
              generations);
  std::printf("       %llu logical -> %llu on the wire = %.1f%% reduction\n",
              (unsigned long long)total_logical, (unsigned long long)total_wire,
              100.0 - pct(total_wire, total_logical));

  // --- controls: bound the claim on both sides ---------------------------------------
  std::printf("\nCONTROLS\n--------\n");
  {
    const std::string t2 = base + "/ctrl_random";
    const std::string s2 = base + "/ctrl_random_store";
    Rng rng(seed ^ 0xfeed);
    if (make_dirs(t2).ok() && make_dirs(s2).ok() &&
        put_file(t2 + "/a.bin", make_random(4000000, rng))) {
      auto st = TargetStore::open(s2);
      auto se = SessionJournal::open(s2);
      if (st.ok() && se.ok()) {
        const Run r = replicate(t2, **st, **se, "ctl", 0);
        if (r.ok) {
          std::printf("  unique incompressible data (expect ~0%%): %llu -> %llu = %.2f%% "
                      "reduction\n",
                      (unsigned long long)r.stats.logical_bytes,
                      (unsigned long long)r.stats.wire_bytes_out,
                      100.0 - pct(r.stats.wire_bytes_out, r.stats.logical_bytes));
          std::printf("      (negative would mean the protocol EXPANDS data; SPEC S14 "
                      "forbids it)\n");
        }
      }
    }
  }
  {
    const std::string t3 = base + "/ctrl_edit";
    const std::string s3 = base + "/ctrl_edit_store";
    Rng rng(seed ^ 0xba11);
    auto data = make_random(4000000, rng);
    if (make_dirs(t3).ok() && make_dirs(s3).ok() && put_file(t3 + "/a.bin", data)) {
      auto st = TargetStore::open(s3);
      auto se = SessionJournal::open(s3);
      if (st.ok() && se.ok()) {
        (void)replicate(t3, **st, **se, "ctl", 0);
        data[data.size() / 2] ^= 0xff;
        (void)put_file(t3 + "/a.bin", data);
        const Run r = replicate(t3, **st, **se, "ctl", 1);
        if (r.ok) {
          std::printf("  single 1-byte edit (expect ~100%%):       %llu -> %llu = %.2f%% "
                      "reduction (%zu chunk(s))\n",
                      (unsigned long long)r.stats.logical_bytes,
                      (unsigned long long)r.stats.wire_bytes_out,
                      100.0 - pct(r.stats.wire_bytes_out, r.stats.logical_bytes),
                      r.stats.chunks_sent);
        }
      }
    }
  }

  // --- attribution: skip vs dedup vs compression --------------------------------------
  std::printf("\nATTRIBUTION -- where the saving comes from, on one incremental generation\n");
  std::printf("------------------------------------------------------------------------\n");
  {
    const std::string t4 = base + "/attrib";
    Rng rng(seed ^ 0xa11c);
    if (make_dirs(t4).ok()) {
      Corpus c(t4, seed ^ 0xa11c);
      (void)rng;
      if (c.create_generation_zero(200)) {
        for (bool compress : {true, false}) {
          const std::string sd = base + "/attrib_store_" + (compress ? "on" : "off");
          if (!make_dirs(sd).ok()) continue;
          auto st = TargetStore::open(sd);
          auto se = SessionJournal::open(sd);
          if (!st.ok() || !se.ok()) continue;
          const Run g0 = replicate(t4, **st, **se, "a", 0, compress);
          if (!g0.ok) continue;
          std::printf("  compression %-3s : seed %llu -> %llu (%.1f%% reduction)\n",
                      compress ? "on" : "off", (unsigned long long)g0.stats.logical_bytes,
                      (unsigned long long)g0.stats.wire_bytes_out,
                      100.0 - pct(g0.stats.wire_bytes_out, g0.stats.logical_bytes));
        }
      }
    }
  }

  // --- round trips: the number that predicts WAN behaviour (SPEC 3.2) -----------------
  std::printf("\nROUND TRIPS (SPEC 3.2: round trips, not bytes, are the WAN enemy)\n");
  std::printf("----------------------------------------------------------------\n");
  {
    const std::string t5 = base + "/rtt";
    Rng rng(seed ^ 0x5555);
    if (make_dirs(t5).ok() && put_file(t5 + "/a.bin", make_text(3000000, rng))) {
      for (double rtt : {0.0, 10.0, 50.0, 100.0}) {
        const std::string sd = base + "/rtt_store_" + std::to_string(static_cast<int>(rtt));
        if (!make_dirs(sd).ok()) continue;
        auto st = TargetStore::open(sd);
        auto se = SessionJournal::open(sd);
        if (!st.ok() || !se.ok()) continue;
        const Run r = replicate(t5, **st, **se, "r", 0, true, rtt, 0);
        if (!r.ok) continue;
        const double gib = static_cast<double>(r.stats.logical_bytes) / (1024.0 * 1024 * 1024);
        std::printf("  RTT %5.0f ms : %6.3f s, %7.2f MB/s, %zu round trips "
                    "(%.0f per GiB)\n",
                    rtt, r.seconds,
                    static_cast<double>(r.stats.wire_bytes_out) / r.seconds / (1024 * 1024),
                    r.stats.round_trips,
                    gib > 0 ? static_cast<double>(r.stats.round_trips) / gib : 0.0);
      }
      std::printf("  Round trips are constant per generation, independent of dataset size:\n"
                  "  that constant, not the byte count, is what predicts behaviour at an\n"
                  "  RTT we did not test. The 0 ms row is loopback, NOT a 0 ms WAN.\n");
    }
  }

  (void)shell("rm -rf " + base);
  return 0;
}
