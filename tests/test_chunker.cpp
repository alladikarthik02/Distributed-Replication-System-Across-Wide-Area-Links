// T1: content-defined chunking.
//
// The two tests that matter most here are not the unit tests:
//
//   * chunker_preserves_boundaries_after_an_insertion -- the property the entire
//     project rests on, measured against a fixed-size chunker as the CONTROL. Without
//     the control the number is unfalsifiable; with it, we can show CDC preserves ~99%
//     of downstream boundaries where fixed-size preserves 0%.
//
//   * chunker_streaming_equals_batch -- the same bytes fed in randomly-sized pieces
//     must produce byte-identical boundaries. The source streams files (SPEC S10) while
//     tests and benchmarks hold whole buffers; if those two paths ever disagreed, a
//     file would chunk differently depending on the read size, every fingerprint would
//     change, and the set difference (SPEC 3.3) would silently degrade to "send
//     everything" with no error anywhere.
#include <algorithm>
#include <cstdio>
#include <numeric>
#include <vector>

#include "test.h"
#include "wanrep/chunker.h"
#include "wanrep/types.h"

using namespace wanrep;

namespace {

// Deterministic PRNG. std::mt19937 would also work, but this is 4 lines, has no
// implementation-defined behaviour to worry about across libstdc++ versions, and makes
// the "reproducible from a seed" claim (SPEC S15) trivially auditable.
struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 0x123456789abcdefull) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
  uint32_t below(uint32_t n) { return static_cast<uint32_t>(next() % n); }
};

std::vector<uint8_t> random_bytes(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(rng.next() >> 24);
  return v;
}

ByteSpan span_of(const std::vector<uint8_t>& v) { return ByteSpan(v.data(), v.size()); }

// Absolute end offsets -- the actual "boundaries". Comparing lengths would be wrong:
// two chunkings can share a length sequence while cutting in different places.
std::vector<size_t> end_offsets(const std::vector<Chunk>& cs) {
  std::vector<size_t> e;
  e.reserve(cs.size());
  for (const auto& c : cs) e.push_back(c.offset + c.length);
  return e;
}

// Fraction of the original boundaries strictly after `after` that survive an insertion
// of one byte at `after`. Boundaries downstream of the edit shift by exactly +1 in the
// modified file, so we shift them back before comparing.
double boundary_preservation(const std::vector<size_t>& orig,
                             const std::vector<size_t>& modified, size_t after) {
  std::vector<size_t> a, b;
  for (size_t o : orig)
    if (o > after) a.push_back(o);
  for (size_t m : modified)
    if (m > after + 1) b.push_back(m - 1);
  if (a.empty()) return 1.0;
  std::vector<size_t> both;
  std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(both));
  return static_cast<double>(both.size()) / static_cast<double>(a.size());
}

// Streams `data` through next_cut() in randomly-sized pieces, exactly as the file
// reader will: keep a buffer starting at the current chunk boundary, ask for a cut,
// and top the buffer up when the answer is "need more".
std::vector<Chunk> chunk_streamed(const Chunker& c, ByteSpan data, uint64_t seed) {
  Rng rng(seed);
  std::vector<Chunk> out;
  std::vector<uint8_t> buf;
  size_t base = 0;  // absolute offset of buf[0]
  size_t fed = 0;   // absolute offset of the next byte to feed
  for (;;) {
    const bool at_eof = (fed == data.size());
    const size_t len = c.next_cut(ByteSpan(buf.data(), buf.size()), at_eof);
    if (len > 0) {
      out.push_back({base, len});
      buf.erase(buf.begin(), buf.begin() + static_cast<long>(len));
      base += len;
      continue;
    }
    if (at_eof) break;
    const size_t piece = std::min<size_t>(1 + rng.below(4096), data.size() - fed);
    buf.insert(buf.end(), data.data() + fed, data.data() + fed + piece);
    fed += piece;
  }
  return out;
}

// Every chunk must be inside [min, max], except the file's short tail, and the chunks
// must tile the input exactly -- no gap, no overlap, nothing dropped.
void check_well_formed(const std::vector<Chunk>& cs, const ChunkParams& p, size_t total) {
  size_t pos = 0;
  for (size_t i = 0; i < cs.size(); i++) {
    TCTX("chunk=" << i << " off=" << cs[i].offset << " len=" << cs[i].length);
    CHECK_EQ(cs[i].offset, pos);
    CHECK_LE(cs[i].length, size_t{p.max});
    CHECK_GT(cs[i].length, size_t{0});
    const bool is_last = (i + 1 == cs.size());
    if (!is_last) CHECK_GE(cs[i].length, size_t{p.min});
    pos += cs[i].length;
  }
  CHECK_EQ(pos, total);
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. The Gear table
// ---------------------------------------------------------------------------

// The table is generated, not pasted. If splitmix64 were mis-transcribed it could
// produce duplicate or zero entries, which would quietly collapse the hash's input
// space -- a chunker that still "works" while cutting far less randomly than intended.
TEST(gear_table_is_well_formed) {
  std::vector<uint64_t> v(chunk_detail::kGear.begin(), chunk_detail::kGear.end());
  CHECK_EQ(v.size(), size_t{256});
  for (size_t i = 0; i < v.size(); i++) {
    TCTX("i=" << i);
    CHECK_NE(v[i], uint64_t{0});
  }
  std::sort(v.begin(), v.end());
  CHECK(std::adjacent_find(v.begin(), v.end()) == v.end());  // all distinct

  // Bit balance: a good table averages ~32 set bits per 64-bit entry. A badly skewed
  // table would bias the masked bits and change the effective cut probability.
  double bits = 0;
  for (uint64_t x : chunk_detail::kGear) bits += static_cast<double>(__builtin_popcountll(x));
  const double mean_bits = bits / 256.0;
  std::printf("    note: gear table mean popcount = %.2f / 64\n", mean_bits);
  CHECK_GT(mean_bits, 28.0);
  CHECK_LT(mean_bits, 36.0);
}

TEST(chunk_params_defaults_are_valid) {
  const ChunkParams p;
  CHECK(p.valid());
  CHECK_EQ(p.min, kMinChunk);
  CHECK_EQ(p.avg, kAvgChunk);
  CHECK_EQ(p.max, kMaxChunk);
  // Bit counts are what set the expected chunk length; assert them rather than the
  // opaque hex values, because the count is the thing with meaning.
  CHECK_EQ(__builtin_popcountll(p.mask_s), 15);
  CHECK_EQ(__builtin_popcountll(p.mask_l), 11);
}

// ---------------------------------------------------------------------------
// 2. Basic contract
// ---------------------------------------------------------------------------

TEST(chunker_is_deterministic) {
  const Chunker c;
  const auto data = random_bytes(1u << 20, testing::seed());
  const auto a = c.chunk_all(span_of(data));
  const auto b = c.chunk_all(span_of(data));
  CHECK_EQ(a.size(), b.size());
  CHECK(end_offsets(a) == end_offsets(b));
}

TEST(chunker_respects_min_and_max_and_tiles_the_input) {
  const Chunker c;
  for (size_t n : {size_t{1} << 16, size_t{1} << 20, size_t{3} * 1000 * 1000}) {
    TCTX("n=" << n);
    const auto data = random_bytes(n, testing::seed() ^ n);
    const auto cs = c.chunk_all(span_of(data));
    check_well_formed(cs, c.params(), n);
  }
}

TEST(chunker_edge_case_sizes) {
  const Chunker c;
  const ChunkParams p = c.params();
  const size_t sizes[] = {0,        1,         2,         p.min - 1, p.min,
                          p.min + 1, p.avg,     p.max - 1, p.max,     p.max + 1,
                          p.max * 2};
  for (size_t n : sizes) {
    TCTX("n=" << n);
    const auto data = random_bytes(n, testing::seed() + n);
    const auto cs = c.chunk_all(span_of(data));
    if (n == 0) {
      CHECK(cs.empty());
      continue;
    }
    check_well_formed(cs, p, n);
    // A buffer that cannot reach the minimum must come back as exactly one chunk.
    if (n <= p.min) {
      CHECK_EQ(cs.size(), size_t{1});
      CHECK_EQ(cs[0].length, n);
    }
  }
}

// ---------------------------------------------------------------------------
// 3. The property the project rests on (SPEC R1.1)
// ---------------------------------------------------------------------------

TEST(chunker_preserves_boundaries_after_an_insertion) {
  const Chunker c;
  const size_t n = 4u << 20;  // 4 MiB
  const auto data = random_bytes(n, testing::seed());
  constexpr size_t kEditAt = 1000;  // early, so nearly every boundary is downstream

  std::vector<uint8_t> edited;
  edited.reserve(n + 1);
  edited.insert(edited.end(), data.begin(), data.begin() + kEditAt);
  edited.push_back(0x5a);  // the one inserted byte
  edited.insert(edited.end(), data.begin() + kEditAt, data.end());

  const double cdc = boundary_preservation(end_offsets(c.chunk_all(span_of(data))),
                                           end_offsets(c.chunk_all(span_of(edited))),
                                           kEditAt);

  // The control. Same data, same edit, fixed 8 KiB blocks.
  const double fixed =
      boundary_preservation(end_offsets(fixed_chunk_all(span_of(data), kAvgChunk)),
                            end_offsets(fixed_chunk_all(span_of(edited), kAvgChunk)),
                            kEditAt);

  std::printf("    note: boundary preservation after a 1-byte insertion --\n"
              "          content-defined: %6.2f%%   fixed-size (control): %6.2f%%\n",
              cdc * 100.0, fixed * 100.0);

  // 100% is the CORRECT answer here, not a suspiciously clean one, and it is worth
  // knowing why. The Gear hash at modified position i depends only on the last ~64
  // bytes, which are original bytes [i-64, i-1]; the same window sits at original
  // position i-1. So once the scan is 64 bytes past the edit, h_modified(i) ==
  // h_original(i-1) identically, and every downstream cut lands at exactly
  // original + 1. Re-synchronisation is not statistical here, it is exact.
  //
  // The control's 0.20% is the same arithmetic run backwards: 4 MiB / 8 KiB = 512
  // fixed boundaries, of which exactly ONE survives -- the end of the file, which
  // shifts by +1 like everything else and so maps back onto itself. 1/512 = 0.195%.
  // Getting precisely the predicted number from the control is what says the
  // measurement machinery is sound rather than accidentally always returning 100%.
  CHECK_GT(cdc, 0.90);    // SPEC R1.1
  CHECK_LT(fixed, 0.05);  // the control must FAIL, or the test measures nothing
}

// The bandwidth claim in miniature: a one-byte edit should make ~one chunk unique, not
// the whole file. This is R1.3 at the chunker level, before any protocol exists.
TEST(chunker_a_one_byte_edit_changes_about_one_chunk) {
  const Chunker c;
  const size_t n = 4u << 20;
  const auto data = random_bytes(n, testing::seed() ^ 0xabc);
  const size_t edit_at = n / 2;

  std::vector<uint8_t> edited = data;
  edited[edit_at] ^= 0xff;  // in-place flip: no shift at all, only content change

  const auto a = c.chunk_all(span_of(data));
  const auto b = c.chunk_all(span_of(edited));

  // Count chunks of `b` whose (offset,length) matches a chunk of `a` AND whose bytes
  // are identical -- i.e. chunks the target would already have.
  size_t identical = 0;
  size_t ai = 0;
  for (const auto& cb : b) {
    while (ai < a.size() && a[ai].offset < cb.offset) ai++;
    if (ai < a.size() && a[ai].offset == cb.offset && a[ai].length == cb.length &&
        std::equal(data.begin() + static_cast<long>(cb.offset),
                   data.begin() + static_cast<long>(cb.offset + cb.length),
                   edited.begin() + static_cast<long>(cb.offset))) {
      identical++;
    }
  }
  const size_t changed = b.size() - identical;
  std::printf("    note: 1-byte in-place edit in a %zu-chunk file -> %zu chunk(s) differ\n",
              b.size(), changed);
  CHECK_GE(b.size(), size_t{100});
  CHECK_LE(changed, size_t{3});  // the edited chunk, plus at most a boundary wobble
}

// ---------------------------------------------------------------------------
// 4. Differential: streaming must equal batch
// ---------------------------------------------------------------------------

TEST(chunker_streaming_equals_batch) {
  const Chunker c;
  for (int trial = 0; trial < 8; trial++) {
    TCTX("trial=" << trial);
    const size_t n = 200000 + (trial * 137001);
    const auto data = random_bytes(n, testing::seed() + static_cast<uint64_t>(trial));
    const auto batch = c.chunk_all(span_of(data));
    const auto streamed =
        chunk_streamed(c, span_of(data), testing::seed() ^ (0x9e37u * (trial + 1)));
    CHECK_EQ(batch.size(), streamed.size());
    CHECK(end_offsets(batch) == end_offsets(streamed));
    check_well_formed(streamed, c.params(), n);
  }
}

// ---------------------------------------------------------------------------
// 5. Pathological content
// ---------------------------------------------------------------------------

// Long runs of a single byte are the classic CDC failure mode, and T1 derived exactly
// why (CHALLENGES.md B3). On a constant run the Gear recurrence unrolls to
//     h_k = (2^k - 1) * G      where G = gear[byte]
// and for k >= 64, 2^k = 0 (mod 2^64), so h_k = -G *forever*. The hash does not merely
// become predictable -- it FREEZES after 64 bytes. Whether a constant run ever cuts is
// therefore decided by a single test per byte value (does -G match the mask?) rather
// than by the data, and measurement says the answer is "never" for all 256 values.
//
// This is benign, and the test asserts why: every forced chunk in a constant run has
// identical content, so they share one fingerprint and collapse to a single stored
// chunk. Sparse files and zero-padded images cost one chunk, not thousands. What it
// does invalidate is the "~8 KiB average" assumption on such data -- which is why
// SPEC 8.9 requires the distribution to be measured per content class before any
// per-chunk overhead figure is quoted.
TEST(chunker_constant_runs_produce_identical_max_size_chunks) {
  const Chunker c;
  const ChunkParams p = c.params();
  for (uint8_t fill : {uint8_t{0x00}, uint8_t{0xff}, uint8_t{'A'}}) {
    TCTX("fill=" << static_cast<int>(fill));
    const std::vector<uint8_t> data(1u << 20, fill);
    const auto cs = c.chunk_all(span_of(data));
    check_well_formed(cs, p, data.size());

    size_t forced = 0;
    for (const auto& ch : cs)
      if (ch.length == p.max) forced++;
    std::printf("    note: fill=0x%02x -> %zu chunks, %zu forced at max (%.0f%%)\n", fill,
                cs.size(), forced,
                cs.empty() ? 0.0 : 100.0 * static_cast<double>(forced) /
                                       static_cast<double>(cs.size()));

    // The derived property: the hash freezes, so EVERY full-size cut is forced.
    CHECK_EQ(forced, cs.size() - 1 + (data.size() % p.max == 0 ? 1 : 0));

    // ...and the reason it does not matter: all those chunks are byte-identical, so
    // they dedup to one. This is the assertion that turns a scary-looking measurement
    // into a bounded, understood cost.
    for (size_t i = 0; i + 1 < cs.size(); i++) {
      TCTX("chunk=" << i);
      CHECK_EQ(cs[i].length, cs[0].length);
    }
  }
}

// The hash-freeze derivation itself, checked directly rather than inferred from chunk
// sizes. If a future change to the Gear table or the shift width broke it, the chunk
// sizes above might still look plausible while the reasoning behind them was wrong.
TEST(gear_hash_freezes_on_a_constant_run_after_64_bytes) {
  for (int b : {0, 1, 0x41, 0xff}) {
    TCTX("byte=" << b);
    const uint64_t g = chunk_detail::kGear[static_cast<size_t>(b)];
    uint64_t h = 0;
    for (int k = 0; k < 64; k++) h = (h << 1) + g;
    const uint64_t frozen = h;
    CHECK_EQ(frozen, uint64_t{0} - g);  // closed form: h_k = -G for k >= 64
    for (int k = 0; k < 500; k++) {
      h = (h << 1) + g;
      CHECK_EQ(h, frozen);  // and it never moves again
    }
  }
}

// Highly repetitive structured data -- closer to real backup content than pure random.
TEST(chunker_handles_repetitive_structured_data) {
  const Chunker c;
  std::vector<uint8_t> data;
  data.reserve(2u << 20);
  const char* line = "2026-08-24T12:00:00Z INFO  replication: chunk sent seq=%08zu\n";
  char buf[128];
  for (size_t i = 0; data.size() < (2u << 20); i++) {
    const int len = std::snprintf(buf, sizeof(buf), line, i);
    data.insert(data.end(), buf, buf + len);
  }
  const auto cs = c.chunk_all(span_of(data));
  check_well_formed(cs, c.params(), data.size());
  CHECK_GT(cs.size(), size_t{1});
}

// ---------------------------------------------------------------------------
// 6. The size distribution (SPEC 8.9 -- must be measured before it is quoted)
// ---------------------------------------------------------------------------

TEST(chunker_size_distribution_is_reported) {
  const Chunker c;
  const ChunkParams p = c.params();
  const size_t n = 32u << 20;  // 32 MiB
  const auto data = random_bytes(n, testing::seed() ^ 0xd15u);
  const auto cs = c.chunk_all(span_of(data));
  REQUIRE(cs.size() > 100);

  std::vector<size_t> len;
  len.reserve(cs.size());
  for (const auto& ch : cs) len.push_back(ch.length);
  len.pop_back();  // the short tail is not a content-defined cut
  std::sort(len.begin(), len.end());
  const double mean =
      static_cast<double>(std::accumulate(len.begin(), len.end(), size_t{0})) /
      static_cast<double>(len.size());
  size_t forced = 0;
  for (size_t l : len)
    if (l == p.max) forced++;

  std::printf("    note: %zu chunks over %zu MiB -- mean %.0f B  p1 %zu  p50 %zu  "
              "p99 %zu  max %zu  forced-at-max %.3f%%\n",
              len.size(), n >> 20, mean, len[len.size() / 100], len[len.size() / 2],
              len[len.size() * 99 / 100], len.back(),
              100.0 * static_cast<double>(forced) / static_cast<double>(len.size()));

  // Loose bounds: the point is the printed distribution, not a tight assertion. These
  // only catch a chunker that has stopped resembling its parameters at all.
  CHECK_GE(len.front(), size_t{p.min});
  CHECK_LE(len.back(), size_t{p.max});
  CHECK_GT(mean, static_cast<double>(p.min));
  CHECK_LT(mean, static_cast<double>(p.max) / 2.0);
}

RUN_ALL()
