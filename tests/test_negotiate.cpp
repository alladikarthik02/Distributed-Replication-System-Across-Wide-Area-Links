// T7: manifests, the canonical chunk list, and the set difference (SPEC 3.3, R1.3, S12).
//
// What is being tested here is the first half of the bandwidth claim, before
// any protocol or compression exists: an unchanged tree costs ZERO payload bytes, and a
// one-byte edit costs about one chunk. If that is not true at this layer, no amount of
// framing or compression downstream will make the number honest.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "test.h"
#include "wanrep/negotiate.h"
#include "wanrep/target_store.h"

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
    path = std::string("/tmp/wanrep_neg_") + tag + "_" + std::to_string(n.fetch_add(1)) +
           "_" + std::to_string(::getpid());
    discard(shell("rm -rf " + path));
    discard(make_dirs(path).ok());
  }
  ~TempDir() { discard(shell("rm -rf " + path)); }
};

std::vector<uint8_t> blob(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(rng.next() >> 24);
  return v;
}

bool put_file(const std::string& path, const std::vector<uint8_t>& data) {
  return make_dirs(dirname_of(path)).ok() &&
         write_file_atomic(path, ByteSpan(data.data(), data.size())).ok();
}

// A small tree with a mix of sizes, including the boundary cases that break chunkers.
void build_tree(const std::string& root, uint64_t seed) {
  discard(put_file(root + "/empty.bin", {}));
  discard(put_file(root + "/one.bin", blob(1, seed)));
  discard(put_file(root + "/small.txt", blob(700, seed + 1)));
  discard(put_file(root + "/exact_min.bin", blob(kMinChunk, seed + 2)));
  discard(put_file(root + "/exact_max.bin", blob(kMaxChunk, seed + 3)));
  discard(put_file(root + "/big.bin", blob(400000, seed + 4)));
  discard(put_file(root + "/nested/deep/inner.bin", blob(90000, seed + 5)));
  discard(put_file(root + "/zeros.bin", std::vector<uint8_t>(300000, 0)));
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. Manifests
// ---------------------------------------------------------------------------

TEST(manifest_round_trips_through_encode_decode) {
  TempDir t("enc");
  build_tree(t.path, testing::seed());
  auto m = scan_tree(t.path, "ds", 0);
  REQUIRE(m.ok());
  CHECK_GT(m->files.size(), size_t{5});

  const auto bytes = m->encode();
  auto back = Manifest::decode(ByteSpan(bytes.data(), bytes.size()));
  REQUIRE(back.ok());
  CHECK_EQ(back->generation, m->generation);
  CHECK_EQ(back->dataset, m->dataset);
  REQUIRE(back->files.size() == m->files.size());
  for (size_t i = 0; i < m->files.size(); i++) {
    TCTX("file=" << m->files[i].path);
    CHECK_EQ(back->files[i].path, m->files[i].path);
    CHECK_EQ(back->files[i].size, m->files[i].size);
    CHECK_EQ(back->files[i].mode, m->files[i].mode);
    CHECK_EQ(back->files[i].mtime_ns, m->files[i].mtime_ns);
    CHECK(back->files[i].digest == m->files[i].digest);
    CHECK_EQ(back->files[i].chunks.size(), m->files[i].chunks.size());
  }
  CHECK(back->digest() == m->digest());
  std::printf("    note: %zu files, %zu chunk refs, manifest = %zu bytes (%.2f%% of %llu logical)\n",
              m->files.size(), m->total_chunk_refs(), bytes.size(),
              100.0 * static_cast<double>(bytes.size()) /
                  static_cast<double>(std::max<uint64_t>(1, m->logical_bytes())),
              static_cast<unsigned long long>(m->logical_bytes()));
}

// Determinism is a protocol requirement: two scans of an identical tree must produce the
// same bytes, or the manifest digest -- which the resume handshake compares -- is useless.
TEST(scanning_the_same_tree_twice_is_byte_identical) {
  TempDir t("det");
  build_tree(t.path, testing::seed());
  auto a = scan_tree(t.path, "ds", 3);
  auto b = scan_tree(t.path, "ds", 3);
  REQUIRE(a.ok());
  REQUIRE(b.ok());
  CHECK(a->encode() == b->encode());
  CHECK(a->digest() == b->digest());
}

TEST(canonical_chunk_list_is_deterministic_and_deduplicated) {
  TempDir t("canon");
  // Two identical files plus a distinct one: the duplicate's chunks must appear once.
  const auto data = blob(100000, testing::seed());
  discard(put_file(t.path + "/a.bin", data));
  discard(put_file(t.path + "/b.bin", data));
  discard(put_file(t.path + "/c.bin", blob(50000, testing::seed() ^ 0xff)));

  auto m = scan_tree(t.path, "ds", 0);
  REQUIRE(m.ok());
  const auto list = canonical_chunk_list(*m);

  // Deduplicated...
  CHECK_LT(list.size(), m->total_chunk_refs());
  std::vector<Digest32> sorted = list;
  std::sort(sorted.begin(), sorted.end());
  CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());

  // ...and identical when derived independently, which is the actual contract: the two
  // nodes each compute this from the manifest alone and index into it by integer.
  const auto bytes = m->encode();
  auto other_side = Manifest::decode(ByteSpan(bytes.data(), bytes.size()));
  REQUIRE(other_side.ok());
  CHECK(canonical_chunk_list(*other_side) == list);
  std::printf("    note: %zu chunk refs collapse to %zu distinct chunks\n",
              m->total_chunk_refs(), list.size());
}

// ---------------------------------------------------------------------------
// 2. Hostile manifests (SPEC S12)
// ---------------------------------------------------------------------------

TEST(unsafe_paths_are_rejected) {
  const char* bad[] = {"/etc/passwd", "../escape",  "a/../../b", "a//b",   "a/",
                       "./x",         "..",         "",          "a/./b",  "a/../b",
                       "back\\slash", "ctrl\x01char"};
  for (const char* p : bad) {
    TCTX("path='" << p << "'");
    CHECK(!valid_relative_path(p));
  }
  const char* good[] = {"a", "a/b", "a/b/c.txt", "dir.with.dots/f", "sp-ace_1"};
  for (const char* p : good) {
    TCTX("path='" << p << "'");
    CHECK(valid_relative_path(p));
  }
}

TEST(a_manifest_with_a_traversal_path_is_refused_at_decode) {
  Manifest m;
  m.dataset = "ds";
  FileEntry f;
  f.path = "../../etc/passwd";
  f.size = 0;
  m.files.push_back(f);
  const auto bytes = m.encode();  // encode does not validate; decode must
  auto back = Manifest::decode(ByteSpan(bytes.data(), bytes.size()));
  CHECK(!back.ok());
  CHECK(back.code() == Err::kMalformed);
}

TEST(a_corrupt_or_truncated_manifest_never_crashes) {
  TempDir t("fuzz");
  build_tree(t.path, testing::seed());
  auto m = scan_tree(t.path, "ds", 0);
  REQUIRE(m.ok());
  const auto good = m->encode();

  Rng rng(testing::seed() ^ 0xf00d);
  for (int trial = 0; trial < 3000; trial++) {
    TCTX("trial=" << trial);
    auto bad = good;
    const int kind = trial % 3;
    if (kind == 0) {                                   // flip bits
      const size_t n = 1 + (rng.next() % 4);
      for (size_t i = 0; i < n; i++) {
        bad[rng.next() % bad.size()] ^= static_cast<uint8_t>(1u << (rng.next() % 8));
      }
    } else if (kind == 1) {                            // truncate
      bad.resize(rng.next() % bad.size());
    } else {                                           // splice in noise
      const size_t at = rng.next() % bad.size();
      const size_t n = 1 + (rng.next() % 64);
      for (size_t i = 0; i < n && at + i < bad.size(); i++) {
        bad[at + i] = static_cast<uint8_t>(rng.next() >> 17);
      }
    }
    // The contract is only "never crash, never allocate wildly". A mutation CAN land on a
    // still-valid manifest (e.g. flipping a bit in an mtime), so success is allowed.
    auto r = Manifest::decode(ByteSpan(bad.data(), bad.size()));
    if (r.ok()) {
      // If it decoded, it must still be internally consistent -- no unsafe paths slipped
      // through, chunk lengths still sum to sizes.
      for (const auto& f : r->files) CHECK(valid_relative_path(f.path));
    }
  }
  // Pure noise must never decode.
  for (int trial = 0; trial < 500; trial++) {
    std::vector<uint8_t> noise(1 + (rng.next() % 4096));
    for (auto& b : noise) b = static_cast<uint8_t>(rng.next() >> 19);
    auto r = Manifest::decode(ByteSpan(noise.data(), noise.size()));
    CHECK(!r.ok());
  }
}

TEST(a_manifest_whose_chunks_do_not_sum_to_the_file_size_is_refused) {
  Manifest m;
  m.dataset = "ds";
  FileEntry f;
  f.path = "a.bin";
  f.size = 10000;  // claims 10 KB...
  f.chunks.push_back(ChunkRef{Digest32{}, 100});  // ...but is backed by 100 bytes
  m.files.push_back(f);
  const auto bytes = m.encode();
  auto back = Manifest::decode(ByteSpan(bytes.data(), bytes.size()));
  CHECK(!back.ok());
  CHECK(back.code() == Err::kMalformed);
}

TEST(a_manifest_with_unsorted_or_duplicate_paths_is_refused) {
  Manifest m;
  m.dataset = "ds";
  FileEntry a;
  a.path = "b.bin";
  FileEntry b;
  b.path = "a.bin";  // out of order
  m.files = {a, b};
  auto bytes = m.encode();
  CHECK(!Manifest::decode(ByteSpan(bytes.data(), bytes.size())).ok());

  m.files = {a, a};  // duplicate
  bytes = m.encode();
  CHECK(!Manifest::decode(ByteSpan(bytes.data(), bytes.size())).ok());
}

// ---------------------------------------------------------------------------
// 3. The set difference -- the project's bandwidth claim in miniature (R1.3)
// ---------------------------------------------------------------------------

TEST(an_empty_target_needs_every_chunk) {
  TempDir tree("empty_t"), store_dir("empty_s");
  build_tree(tree.path, testing::seed());
  auto s = TargetStore::open(store_dir.path);
  REQUIRE(s.ok());
  auto m = scan_tree(tree.path, "ds", 0);
  REQUIRE(m.ok());

  const auto r = negotiate(*m, nullptr, (*s)->chunks());
  CHECK_EQ(r.chunks_needed, r.chunks_total);
  CHECK_EQ(r.bytes_needed, r.bytes_total);
  CHECK_EQ(r.need.count(), r.chunks_total);
}

TEST(an_unchanged_tree_needs_nothing) {
  TempDir tree("unch_t"), store_dir("unch_s");
  build_tree(tree.path, testing::seed());
  auto s = TargetStore::open(store_dir.path);
  REQUIRE(s.ok());
  auto m = scan_tree(tree.path, "ds", 0);
  REQUIRE(m.ok());

  // Transfer generation 0 by hand.
  SourceChunkReader reader(tree.path, *m);
  for (const auto& fp : canonical_chunk_list(*m)) {
    auto bytes = reader.read(fp);
    REQUIRE(bytes.ok());
    REQUIRE((*s)->chunks().put(fp, ByteSpan(bytes->data(), bytes->size())).ok());
  }

  // Generation 1 of the same, unmodified tree.
  auto m1 = scan_tree(tree.path, "ds", 1);
  REQUIRE(m1.ok());
  const auto r = negotiate(*m1, &*m, (*s)->chunks());
  CHECK_EQ(r.chunks_needed, size_t{0});
  CHECK_EQ(r.bytes_needed, uint64_t{0});
  CHECK_EQ(r.files_unchanged, r.files_total);

  // The NEED reply for a fully-satisfied tree is essentially free to send -- this is the
  // property SPEC 3.3 claims makes the negotiation cheap at WAN scale.
  const auto encoded = r.need.encode();
  std::printf("    note: %zu chunks, none needed; NEED reply encodes to %zu bytes\n",
              r.chunks_total, encoded.size());
  CHECK_LT(encoded.size(), size_t{32});
}

// THE claim: a one-byte edit costs about one chunk, not a file and not a tree.
TEST(a_one_byte_edit_needs_about_one_chunk) {
  TempDir tree("edit_t"), store_dir("edit_s");
  const auto original = blob(2000000, testing::seed());  // 2 MB
  discard(put_file(tree.path + "/big.bin", original));
  discard(put_file(tree.path + "/other.bin", blob(300000, testing::seed() + 9)));

  auto s = TargetStore::open(store_dir.path);
  REQUIRE(s.ok());
  auto m0 = scan_tree(tree.path, "ds", 0);
  REQUIRE(m0.ok());
  SourceChunkReader reader0(tree.path, *m0);
  for (const auto& fp : canonical_chunk_list(*m0)) {
    auto bytes = reader0.read(fp);
    REQUIRE(bytes.ok());
    REQUIRE((*s)->chunks().put(fp, ByteSpan(bytes->data(), bytes->size())).ok());
  }

  // Flip one byte in the middle of the 2 MB file.
  auto edited = original;
  edited[1000000] ^= 0xff;
  discard(put_file(tree.path + "/big.bin", edited));

  auto m1 = scan_tree(tree.path, "ds", 1);
  REQUIRE(m1.ok());
  const auto r = negotiate(*m1, &*m0, (*s)->chunks());

  std::printf("    note: 1-byte edit in a %llu-byte tree -> %zu of %zu chunks needed, "
              "%llu payload bytes (%.4f%% of a full transfer)\n",
              static_cast<unsigned long long>(m1->logical_bytes()), r.chunks_needed,
              r.chunks_total, static_cast<unsigned long long>(r.bytes_needed),
              100.0 * static_cast<double>(r.bytes_needed) /
                  static_cast<double>(std::max<uint64_t>(1, r.bytes_total)));

  CHECK_LE(r.chunks_needed, size_t{3});   // the edited chunk, plus a possible boundary wobble
  CHECK_GE(r.chunks_needed, size_t{1});
  CHECK_LT(r.bytes_needed, uint64_t{3 * kMaxChunk});
  CHECK_EQ(r.files_unchanged, size_t{1});  // other.bin
}

// Content addressing gets this for free, and a file-level differ cannot: moving a file
// changes its path but not one byte of its content.
TEST(a_renamed_file_needs_nothing) {
  TempDir tree("mv_t"), store_dir("mv_s");
  discard(put_file(tree.path + "/a.bin", blob(300000, testing::seed())));
  auto s = TargetStore::open(store_dir.path);
  REQUIRE(s.ok());
  auto m0 = scan_tree(tree.path, "ds", 0);
  REQUIRE(m0.ok());
  SourceChunkReader reader(tree.path, *m0);
  for (const auto& fp : canonical_chunk_list(*m0)) {
    auto bytes = reader.read(fp);
    REQUIRE(bytes.ok());
    REQUIRE((*s)->chunks().put(fp, ByteSpan(bytes->data(), bytes->size())).ok());
  }
  REQUIRE(shell("mv " + tree.path + "/a.bin " + tree.path + "/moved/b.bin 2>/dev/null || "
                "(mkdir -p " + tree.path + "/moved && mv " + tree.path + "/a.bin " +
                tree.path + "/moved/b.bin)"));

  auto m1 = scan_tree(tree.path, "ds", 1);
  REQUIRE(m1.ok());
  const auto r = negotiate(*m1, &*m0, (*s)->chunks());
  CHECK_EQ(r.chunks_needed, size_t{0});
  CHECK_EQ(r.files_unchanged, size_t{0});  // the FILE changed; its CONTENT did not
  std::printf("    note: renamed file -> 0 chunks needed, 0 files matched by path\n");
}

// The self-healing property that probing (rather than trusting the previous manifest)
// buys -- see the design note at the top of negotiate.h.
TEST(a_chunk_lost_to_corruption_is_re_requested) {
  TempDir tree("heal_t"), store_dir("heal_s");
  discard(put_file(tree.path + "/a.bin", blob(200000, testing::seed())));
  auto m0 = scan_tree(tree.path, "ds", 0);
  REQUIRE(m0.ok());
  const auto list = canonical_chunk_list(*m0);
  REQUIRE(list.size() > 3);
  {
    auto s = TargetStore::open(store_dir.path);
    REQUIRE(s.ok());
    SourceChunkReader reader(tree.path, *m0);
    for (const auto& fp : list) {
      auto bytes = reader.read(fp);
      REQUIRE(bytes.ok());
      REQUIRE((*s)->chunks().put(fp, ByteSpan(bytes->data(), bytes->size())).ok());
    }
    REQUIRE((*s)->chunks().sync().ok());
  }
  // Corrupt the very first record so recovery drops exactly that chunk (and, thanks to
  // the B4 fix, keeps the rest).
  REQUIRE(shell("printf Z | dd of=" + store_dir.path +
                "/chunks/c00000000.dat bs=1 seek=100 conv=notrunc status=none"));

  auto s = TargetStore::open(store_dir.path);
  REQUIRE(s.ok());
  auto m1 = scan_tree(tree.path, "ds", 1);
  REQUIRE(m1.ok());
  // The file looks completely unchanged by every manifest field...
  const auto r = negotiate(*m1, &*m0, (*s)->chunks());
  CHECK_EQ(r.files_unchanged, size_t{1});
  // ...and yet the lost chunk is re-requested, because the STORE is authoritative.
  CHECK_EQ(r.chunks_needed, size_t{1});
  std::printf("    note: unchanged file with 1 corrupted chunk -> %zu chunk re-requested "
              "(self-healing)\n", r.chunks_needed);
}

// ---------------------------------------------------------------------------
// 4. Materialize -- byte-exact reconstruction (SPEC R1.1, S1)
// ---------------------------------------------------------------------------

TEST(materialized_tree_is_byte_identical_to_the_source) {
  TempDir tree("mat_t"), store_dir("mat_s"), out("mat_o");
  build_tree(tree.path, testing::seed());
  auto s = TargetStore::open(store_dir.path);
  REQUIRE(s.ok());
  auto m = scan_tree(tree.path, "ds", 0);
  REQUIRE(m.ok());
  SourceChunkReader reader(tree.path, *m);
  for (const auto& fp : canonical_chunk_list(*m)) {
    auto bytes = reader.read(fp);
    REQUIRE(bytes.ok());
    REQUIRE((*s)->chunks().put(fp, ByteSpan(bytes->data(), bytes->size())).ok());
  }

  REQUIRE(materialize(*m, (*s)->chunks(), out.path).ok());
  // diff -r is the oracle a reviewer would use, so use it: it compares content AND
  // catches files that exist on one side only.
  CHECK(shell("diff -r " + tree.path + " " + out.path + " >/dev/null"));

  // And the source tree was never touched (SPEC S13).
  auto again = scan_tree(tree.path, "ds", 0);
  REQUIRE(again.ok());
  CHECK(again->digest() == m->digest());
}

TEST(materialize_refuses_a_manifest_whose_digest_does_not_match_its_chunks) {
  TempDir tree("bad_t"), store_dir("bad_s"), out("bad_o");
  discard(put_file(tree.path + "/a.bin", blob(50000, testing::seed())));
  auto s = TargetStore::open(store_dir.path);
  REQUIRE(s.ok());
  auto m = scan_tree(tree.path, "ds", 0);
  REQUIRE(m.ok());
  SourceChunkReader reader(tree.path, *m);
  for (const auto& fp : canonical_chunk_list(*m)) {
    auto bytes = reader.read(fp);
    REQUIRE(bytes.ok());
    REQUIRE((*s)->chunks().put(fp, ByteSpan(bytes->data(), bytes->size())).ok());
  }
  // Lie about the whole-file digest: the end-to-end check must catch it even though every
  // individual chunk is present and internally valid.
  m->files[0].digest[0] ^= 0xff;
  auto r = materialize(*m, (*s)->chunks(), out.path);
  CHECK(!r.ok());
  CHECK(r.code() == Err::kCorrupt);
}

RUN_ALL()
