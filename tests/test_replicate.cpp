// T8: end-to-end replication (SPEC R1.1, R1.2, R1.3, R1.4, S1, S2, S17).
//
// Everything before this tested a layer. This tests the CLAIM: a tree on one node appears
// byte-identical on another, only the changed chunks crossed the wire, and the bytes that
// did cross were counted by the transport itself rather than modelled.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "test.h"
#include "wanrep/protocol.h"
#include "wanrep/tcp_link.h"

using namespace wanrep;

namespace {

inline void discard(bool) {}
bool shell(const std::string& cmd) { return std::system(cmd.c_str()) == 0; }

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

struct TempDir {
  std::string path;
  explicit TempDir(const char* tag) {
    static std::atomic<int> n{0};
    path = std::string("/tmp/wanrep_rep_") + tag + "_" + std::to_string(n.fetch_add(1)) +
           "_" + std::to_string(::getpid());
    discard(shell("rm -rf " + path));
    discard(make_dirs(path).ok());
  }
  ~TempDir() { discard(shell("rm -rf " + path)); }
};

std::vector<uint8_t> random_blob(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(rng.next() >> 24);
  return v;
}

// Text-like content: compressible, which is what makes the compression half of the
// bandwidth claim measurable rather than theoretical.
std::vector<uint8_t> textish(size_t n, uint64_t seed) {
  static const char* words[] = {"replication", "chunk", "target", "source", "manifest",
                                "generation",  "the",   "and",    "a",      "commit",
                                "fingerprint", "wide",  "area",   "link",   "resume"};
  Rng rng(seed);
  std::string s;
  while (s.size() < n) {
    s += words[rng.next() % 15];
    s += (rng.next() % 8 == 0) ? "\n" : " ";
  }
  s.resize(n);
  return std::vector<uint8_t>(s.begin(), s.end());
}

bool put_file(const std::string& path, const std::vector<uint8_t>& data) {
  return make_dirs(dirname_of(path)).ok() &&
         write_file_atomic(path, ByteSpan(data.data(), data.size())).ok();
}

void build_tree(const std::string& root, uint64_t seed) {
  discard(put_file(root + "/empty.bin", {}));
  discard(put_file(root + "/one.bin", random_blob(1, seed)));
  discard(put_file(root + "/notes.txt", textish(120000, seed + 1)));
  discard(put_file(root + "/doc/readme.txt", textish(300000, seed + 2)));
  discard(put_file(root + "/data/random.bin", random_blob(250000, seed + 3)));
  discard(put_file(root + "/data/nested/deep/x.bin", random_blob(90000, seed + 4)));
  discard(put_file(root + "/zeros.bin", std::vector<uint8_t>(200000, 0)));
  discard(put_file(root + "/exact_max.bin", random_blob(kMaxChunk, seed + 5)));
}

// Runs one replication over an in-process link pair, with the target on its own thread.
struct RunResult {
  Result<JobStats> stats = err(Err::kCancelled, "not run");
  Result<void> target_result = Result<void>{};
};

RunResult replicate_once(const std::string& tree, TargetStore& store, SessionJournal& sessions,
                         SourceJob::Options opt, size_t chunk_limit = 0) {
  auto [a, b] = MemoryLink::make_pair(chunk_limit);
  RunResult rr;
  std::thread target([&] {
    TargetServer server(store, sessions);
    rr.target_result = server.serve(*b);
  });
  rr.stats = SourceJob::run(*a, tree, opt);
  a->close();
  target.join();
  return rr;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. The core claim
// ---------------------------------------------------------------------------

TEST(a_tree_replicates_byte_identically) {
  TempDir tree("t"), store_dir("s"), out("o");
  build_tree(tree.path, testing::seed());
  auto store = TargetStore::open(store_dir.path);
  REQUIRE(store.ok());
  auto sessions = SessionJournal::open(store_dir.path);
  REQUIRE(sessions.ok());

  SourceJob::Options opt;
  opt.dataset = "backup";
  opt.generation = 0;
  auto rr = replicate_once(tree.path, **store, **sessions, opt);
  REQUIRE(rr.stats.ok());
  CHECK(rr.target_result.ok());

  // The generation is committed and visible.
  CHECK((*store)->generations().is_committed("backup", 0));
  CHECK((*store)->generations().is_prefix_consistent("backup"));

  // And it materializes byte-for-byte.
  auto mb = (*store)->generations().manifest_bytes("backup", 0);
  REQUIRE(mb.ok());
  auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
  REQUIRE(m.ok());
  REQUIRE(materialize(*m, (*store)->chunks(), out.path).ok());
  CHECK(shell("diff -r " + tree.path + " " + out.path + " >/dev/null"));

  auto v = (*store)->verify(true);
  REQUIRE(v.ok());
  CHECK_EQ(v->problems, size_t{0});

  const auto& s = rr.stats;
  std::printf("    note: %llu logical -> %llu wire bytes (%.1f%%), %zu/%zu chunks sent, "
              "%zu round trips, %zu frames\n",
              static_cast<unsigned long long>(s->logical_bytes),
              static_cast<unsigned long long>(s->wire_bytes_out),
              100.0 * static_cast<double>(s->wire_bytes_out) /
                  static_cast<double>(std::max<uint64_t>(1, s->logical_bytes)),
              s->chunks_sent, s->chunks_total, s->round_trips, s->frames_out);
}

// Short transfers are the normal case on a socket (SPEC 2.5: a 4 MiB send moved 6144
// bytes). Running the whole protocol through a transport that moves a few bytes at a time
// is the cheapest way to prove no layer assumed otherwise.
TEST(replication_survives_pathologically_short_transfers) {
  for (size_t limit : {size_t{1}, size_t{7}, size_t{997}}) {
    TCTX("chunk_limit=" << limit);
    TempDir tree("st"), store_dir("ss"), out("so");
    discard(put_file(tree.path + "/a.txt", textish(40000, testing::seed())));
    discard(put_file(tree.path + "/b.bin", random_blob(30000, testing::seed() + 1)));
    auto store = TargetStore::open(store_dir.path);
    REQUIRE(store.ok());
    auto sessions = SessionJournal::open(store_dir.path);
    REQUIRE(sessions.ok());

    SourceJob::Options opt;
    opt.dataset = "ds";
    auto rr = replicate_once(tree.path, **store, **sessions, opt, limit);
    REQUIRE(rr.stats.ok());

    auto mb = (*store)->generations().manifest_bytes("ds", 0);
    REQUIRE(mb.ok());
    auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
    REQUIRE(m.ok());
    REQUIRE(materialize(*m, (*store)->chunks(), out.path).ok());
    CHECK(shell("diff -r " + tree.path + " " + out.path + " >/dev/null"));
  }
}

// ---------------------------------------------------------------------------
// 2. The bandwidth claim, measured on the wire (R1.3, R1.4)
// ---------------------------------------------------------------------------

TEST(an_unchanged_generation_costs_almost_nothing) {
  TempDir tree("u"), store_dir("us");
  build_tree(tree.path, testing::seed());
  auto store = TargetStore::open(store_dir.path);
  REQUIRE(store.ok());
  auto sessions = SessionJournal::open(store_dir.path);
  REQUIRE(sessions.ok());

  SourceJob::Options opt;
  opt.dataset = "ds";
  opt.generation = 0;
  auto first = replicate_once(tree.path, **store, **sessions, opt);
  REQUIRE(first.stats.ok());

  opt.generation = 1;
  auto second = replicate_once(tree.path, **store, **sessions, opt);
  REQUIRE(second.stats.ok());

  CHECK_EQ(second.stats->chunks_sent, size_t{0});
  CHECK_EQ(second.stats->payload_bytes_sent, uint64_t{0});
  // The wire cost of an unchanged generation is the manifest plus the handshake -- which
  // SPEC 8.3 names as the dominant cost at high similarity, rather than burying it.
  std::printf("    note: unchanged generation: %llu wire bytes for %llu logical "
              "(manifest %llu of that = %.0f%%)\n",
              static_cast<unsigned long long>(second.stats->wire_bytes_out),
              static_cast<unsigned long long>(second.stats->logical_bytes),
              static_cast<unsigned long long>(second.stats->manifest_bytes_sent),
              100.0 * static_cast<double>(second.stats->manifest_bytes_sent) /
                  static_cast<double>(std::max<uint64_t>(1, second.stats->wire_bytes_out)));
  CHECK_LT(second.stats->wire_bytes_out, second.stats->logical_bytes / 10);
}

TEST(a_one_byte_edit_costs_about_one_chunk_on_the_wire) {
  TempDir tree("e"), store_dir("es"), out("eo");
  const auto original = random_blob(1500000, testing::seed());
  discard(put_file(tree.path + "/big.bin", original));
  discard(put_file(tree.path + "/other.txt", textish(200000, testing::seed() + 1)));

  auto store = TargetStore::open(store_dir.path);
  REQUIRE(store.ok());
  auto sessions = SessionJournal::open(store_dir.path);
  REQUIRE(sessions.ok());

  SourceJob::Options opt;
  opt.dataset = "ds";
  opt.generation = 0;
  REQUIRE(replicate_once(tree.path, **store, **sessions, opt).stats.ok());

  auto edited = original;
  edited[700000] ^= 0xff;
  discard(put_file(tree.path + "/big.bin", edited));

  opt.generation = 1;
  auto rr = replicate_once(tree.path, **store, **sessions, opt);
  REQUIRE(rr.stats.ok());
  CHECK_LE(rr.stats->chunks_sent, size_t{3});
  CHECK_GE(rr.stats->chunks_sent, size_t{1});
  std::printf("    note: 1-byte edit -> %zu chunks, %llu payload bytes, %llu on the wire "
              "(%.3f%% of the %llu-byte tree)\n",
              rr.stats->chunks_sent,
              static_cast<unsigned long long>(rr.stats->payload_bytes_sent),
              static_cast<unsigned long long>(rr.stats->wire_bytes_out),
              100.0 * static_cast<double>(rr.stats->wire_bytes_out) /
                  static_cast<double>(rr.stats->logical_bytes),
              static_cast<unsigned long long>(rr.stats->logical_bytes));

  // ...and generation 1 still materializes correctly, which is the part that matters.
  auto mb = (*store)->generations().manifest_bytes("ds", 1);
  REQUIRE(mb.ok());
  auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
  REQUIRE(m.ok());
  REQUIRE(materialize(*m, (*store)->chunks(), out.path).ok());
  CHECK(shell("diff -r " + tree.path + " " + out.path + " >/dev/null"));
}

TEST(compression_reduces_the_wire_cost_of_compressible_data) {
  TempDir tree_c("c"), store_c("cs"), tree_r("r"), store_r("rs");
  // Same size, different compressibility.
  discard(put_file(tree_c.path + "/text.txt", textish(2000000, testing::seed())));
  discard(put_file(tree_r.path + "/rand.bin", random_blob(2000000, testing::seed())));

  auto compressed_wire = [&](const std::string& tree, const std::string& sd, bool compress) {
    auto store = TargetStore::open(sd);
    if (!store.ok()) return uint64_t{0};
    auto sessions = SessionJournal::open(sd);
    if (!sessions.ok()) return uint64_t{0};
    SourceJob::Options opt;
    opt.dataset = "ds";
    opt.compress = compress;
    auto rr = replicate_once(tree, **store, **sessions, opt);
    return rr.stats.ok() ? rr.stats->wire_bytes_out : uint64_t{0};
  };

  TempDir store_c2("cs2"), store_r2("rs2");
  const uint64_t text_on = compressed_wire(tree_c.path, store_c.path, true);
  const uint64_t text_off = compressed_wire(tree_c.path, store_c2.path, false);
  const uint64_t rand_on = compressed_wire(tree_r.path, store_r.path, true);
  const uint64_t rand_off = compressed_wire(tree_r.path, store_r2.path, false);
  REQUIRE(text_on > 0 && text_off > 0 && rand_on > 0 && rand_off > 0);

  std::printf("    note: text 2 MB  -> %llu wire compressed vs %llu raw (%.1f%% saved)\n",
              static_cast<unsigned long long>(text_on),
              static_cast<unsigned long long>(text_off),
              100.0 * (1.0 - static_cast<double>(text_on) / static_cast<double>(text_off)));
  std::printf("    note: random 2 MB -> %llu wire compressed vs %llu raw (%.1f%% saved)\n",
              static_cast<unsigned long long>(rand_on),
              static_cast<unsigned long long>(rand_off),
              100.0 * (1.0 - static_cast<double>(rand_on) / static_cast<double>(rand_off)));

  CHECK_LT(text_on, text_off);  // compressible data must get smaller...
  // ...and SPEC S14: incompressible data must NOT get bigger. A few bytes of frame
  // overhead is fine; expansion is not.
  CHECK_LE(rand_on, rand_off + rand_off / 100);
}

// ---------------------------------------------------------------------------
// 3. The target never trusts the source (SPEC S17)
// ---------------------------------------------------------------------------

TEST(a_source_that_mislabels_a_chunk_is_rejected_and_nothing_is_committed) {
  TempDir tree("ev"), store_dir("evs");
  discard(put_file(tree.path + "/a.bin", random_blob(100000, testing::seed())));
  auto store = TargetStore::open(store_dir.path);
  REQUIRE(store.ok());
  auto sessions = SessionJournal::open(store_dir.path);
  REQUIRE(sessions.ok());

  // Drive the protocol by hand up to the point of sending a corrupted batch.
  auto [a, b] = MemoryLink::make_pair();
  std::atomic<bool> target_failed{false};
  std::thread target([&] {
    TargetServer server(**store, **sessions);
    target_failed = !server.serve(*b).ok();
  });

  FrameWriter w(*a);
  FrameReader r(*a);
  auto m = scan_tree(tree.path, "ds", 0);
  REQUIRE(m.ok());
  const auto mb = m->encode();
  const Digest32 md = sha256(ByteSpan(mb.data(), mb.size()));

  std::vector<uint8_t> hello;
  put_varint(hello, kProtocolVersion);
  put_varint(hello, kMinChunk);
  put_varint(hello, kAvgChunk);
  put_varint(hello, kMaxChunk);
  REQUIRE(w.write(FrameType::kHello, 0, ByteSpan(hello.data(), hello.size())).ok());
  REQUIRE(r.next().ok());

  std::vector<uint8_t> start;
  proto::put_str(start, "ds");
  put_varint(start, 0);
  start.insert(start.end(), md.begin(), md.end());
  REQUIRE(w.write(FrameType::kSessionStart, 0, ByteSpan(start.data(), start.size())).ok());
  REQUIRE(proto::send_blob(w, FrameType::kManifest, ByteSpan(mb.data(), mb.size())).ok());
  REQUIRE(r.next().ok());                                             // SESSION_ACK
  REQUIRE(proto::recv_blob(r, FrameType::kNeed, kMaxNeedBytes).ok()); // NEED

  // Send a batch of the RIGHT length but the WRONG bytes for plan position 0.
  std::vector<uint8_t> batch;
  const auto lie = random_blob(9000, testing::seed() ^ 0xdead);
  put_varint(batch, lie.size());
  batch.insert(batch.end(), lie.begin(), lie.end());
  (void)w.write(FrameType::kChunks, 0, ByteSpan(batch.data(), batch.size()), 0,
                static_cast<uint32_t>(batch.size()));
  a->close();
  target.join();

  CHECK(target_failed);  // the target refused rather than storing it
  CHECK(!(*store)->generations().is_committed("ds", 0));
  auto v = (*store)->verify(true);
  REQUIRE(v.ok());
  CHECK_EQ(v->problems, size_t{0});  // and the store is still clean
  std::printf("    note: mislabelled chunk rejected; nothing committed, store verifies clean\n");
}

// ---------------------------------------------------------------------------
// 4. Over a real socket
// ---------------------------------------------------------------------------

TEST(replication_works_over_real_tcp) {
  TempDir tree("tcp"), store_dir("tcps"), out("tcpo");
  build_tree(tree.path, testing::seed());
  auto store = TargetStore::open(store_dir.path);
  REQUIRE(store.ok());
  auto sessions = SessionJournal::open(store_dir.path);
  REQUIRE(sessions.ok());

  auto listener = TcpLink::Listener::bind("127.0.0.1", 0);
  REQUIRE(listener.ok());
  const uint16_t port = listener->port();

  std::atomic<bool> served{false};
  std::thread target([&] {
    auto conn = listener->accept();
    if (!conn.ok()) return;
    TargetServer server(**store, **sessions);
    served = server.serve(**conn).ok();
  });

  auto client = TcpLink::connect("127.0.0.1", port);
  REQUIRE(client.ok());
  SourceJob::Options opt;
  opt.dataset = "ds";
  auto stats = SourceJob::run(**client, tree.path, opt);
  (*client)->close();
  target.join();

  REQUIRE(stats.ok());
  CHECK(served);
  auto mb = (*store)->generations().manifest_bytes("ds", 0);
  REQUIRE(mb.ok());
  auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
  REQUIRE(m.ok());
  REQUIRE(materialize(*m, (*store)->chunks(), out.path).ok());
  CHECK(shell("diff -r " + tree.path + " " + out.path + " >/dev/null"));
  std::printf("    note: over TCP on port %u: %llu wire bytes, %zu round trips\n", port,
              static_cast<unsigned long long>(stats->wire_bytes_out), stats->round_trips);
}

RUN_ALL()
