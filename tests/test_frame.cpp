// T2: the wire protocol -- varints, the run-length need-set, and the frame codec.
//
// Three of these tests carry more weight than the rest, and they are the reason the file
// is organized the way it is:
//
//   * frame_short_transfer_round_trip -- every round trip is re-run through
//     MemoryLink::make_pair(N) for N in {1, 3, 7, 1000}. SPEC 2.5 measured a single
//     send() of 4 MiB moving 6 144 bytes. A framing layer exercised only against a
//     transport that transfers everything is a framing layer whose write_all/read_exact
//     loops have never actually looped, and the bug it hides -- a frame cut in half,
//     with the peer blocked forever on bytes that will never arrive -- is invisible in
//     every local test and fatal on a real link.
//
//   * frame_header_bitflip_fuzz -- 256 mutations per frame, one per bit of the header,
//     each asserted to produce a clean typed error. This is the direct test of SPEC S7:
//     wire_len decides an allocation, so a flipped bit in it must be caught by
//     header_crc BEFORE the length is used, not after.
//
//   * frame_rejects_giant_wire_len -- the specific attack S7 names. The proof that no
//     allocation happened is that the reader consumed exactly 32 bytes and never asked
//     the transport for the 4 GiB it was promised; an RSS delta over a thousand such
//     frames is printed alongside as corroboration.
//
// Everything randomized is seeded from testing::seed() and wrapped in TCTX() so a red
// line names the iteration that produced it (SPEC S15).
#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "test.h"
#include "wanrep/crc32c.h"
#include "wanrep/frame.h"
#include "wanrep/link.h"
#include "wanrep/needset.h"
#include "wanrep/types.h"
#include "wanrep/varint.h"

using namespace wanrep;

namespace {

// xorshift64*, same as tests/test_chunker.cpp: four lines, no implementation-defined
// behaviour across libstdc++ versions, and the "reproducible from a seed" claim (SPEC
// S15) is auditable by reading it.
struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 0x123456789abcdefull) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
  uint32_t below(uint32_t n) { return n ? static_cast<uint32_t>(next() % n) : 0; }
  uint8_t byte() { return static_cast<uint8_t>(next() >> 24); }
};

const char* frame_type_name(FrameType t) {
  switch (t) {
    case FrameType::kHello: return "HELLO";
    case FrameType::kHelloAck: return "HELLO_ACK";
    case FrameType::kSessionStart: return "SESSION_START";
    case FrameType::kSessionResume: return "SESSION_RESUME";
    case FrameType::kSessionAck: return "SESSION_ACK";
    case FrameType::kManifest: return "MANIFEST";
    case FrameType::kNeed: return "NEED";
    case FrameType::kChunks: return "CHUNKS";
    case FrameType::kCheckpoint: return "CHECKPOINT";
    case FrameType::kGenCommit: return "GEN_COMMIT";
    case FrameType::kCommitAck: return "COMMIT_ACK";
    case FrameType::kError: return "ERROR";
    case FrameType::kBye: return "BYE";
  }
  return "?";
}

// The lowest flag bit this protocol version does NOT define, derived from the codec's own
// table rather than hard-coded.
//
// This is not tidiness. The "undefined flag bit" case below was originally written as the
// literal 0x02, which was undefined when it was written. A later task defined that exact
// bit (kFlagLastSlice, types.h), and the assertion "an undefined bit is rejected" quietly
// turned into "a defined bit is rejected" -- a red suite whose failure said nothing about
// the codec. A test about unknown bits has to ask the codec which bits are unknown, or it
// decays into a test about a number.
constexpr uint8_t lowest_undefined_flag_bit() {
  for (int b = 0; b < 8; b++) {
    const uint8_t m = static_cast<uint8_t>(1u << b);
    if ((kKnownFrameFlags & m) == 0) return m;
  }
  return 0;
}
static_assert(lowest_undefined_flag_bit() != 0,
              "every flag bit is defined; the unknown-bit rejection cases need rewriting");
inline constexpr uint8_t kUndefinedFlagBit = lowest_undefined_flag_bit();

const FrameType kAllTypes[] = {
    FrameType::kHello,      FrameType::kHelloAck,   FrameType::kSessionStart,
    FrameType::kSessionResume, FrameType::kSessionAck, FrameType::kManifest,
    FrameType::kNeed,       FrameType::kChunks,     FrameType::kCheckpoint,
    FrameType::kGenCommit,  FrameType::kCommitAck,  FrameType::kError,
    FrameType::kBye};

std::vector<uint8_t> random_bytes(size_t n, Rng& rng) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = rng.byte();
  return v;
}

// --- transport helpers -------------------------------------------------------------
//
// Every helper drives the REAL FrameWriter rather than hand-rolling a second serializer,
// so a mutation test can never end up exercising a header layout that production does
// not produce.

struct Pipe {
  std::shared_ptr<MemoryLink> tx, rx;
  explicit Pipe(size_t chunk_limit = 0) {
    auto p = MemoryLink::make_pair(chunk_limit);
    tx = p.first;
    rx = p.second;
  }
};

// Serializes one frame to bytes by writing it into a MemoryLink and draining the far
// side. Used by the mutation tests, which need the exact on-wire image.
std::vector<uint8_t> serialize_frame(FrameType t, uint64_t seq, ByteSpan payload,
                                     uint8_t flags = 0, uint32_t raw_len = 0) {
  Pipe p;
  FrameWriter w(*p.tx);
  auto wr = w.write(t, seq, payload, flags, raw_len);
  if (!wr.ok()) return {};
  p.tx->close();
  std::vector<uint8_t> out;
  uint8_t buf[8192];
  for (;;) {
    auto r = p.rx->read_some(buf, sizeof(buf));
    if (!r.ok()) break;
    out.insert(out.end(), buf, buf + *r);
  }
  return out;
}

// Feeds a raw byte image to a FrameReader and returns the first result. The transport is
// closed cleanly after the bytes, so a reader that wants more than was supplied reports
// a truncation rather than blocking forever.
Result<Frame> read_one(ByteSpan bytes, size_t chunk_limit = 0) {
  Pipe p(chunk_limit);
  auto wr = write_all(*p.tx, bytes);
  if (!wr.ok()) return wr.error();
  p.tx->close();
  FrameReader r(*p.rx);
  return r.next();
}

bool is_clean_frame_error(Err e) {
  return e == Err::kBadHeaderCrc || e == Err::kBadMagic || e == Err::kTooLarge ||
         e == Err::kMalformed || e == Err::kBadPayloadCrc || e == Err::kShortRead ||
         e == Err::kClosed || e == Err::kReset;
}

// Resident set size in bytes, from /proc/self/statm (field 2 = resident pages). Used
// only to corroborate "no large allocation happened"; the load-bearing assertion in that
// test is the byte counter on the link, which cannot be fooled by an allocator that
// happens not to touch the pages it reserved.
size_t rss_bytes() {
  std::FILE* f = std::fopen("/proc/self/statm", "r");
  if (!f) return 0;
  unsigned long total = 0, resident = 0;
  const int n = std::fscanf(f, "%lu %lu", &total, &resident);
  std::fclose(f);
  if (n != 2) return 0;
  return static_cast<size_t>(resident) * 4096;
}

}  // namespace

// ===================================================================================
// varint
// ===================================================================================

TEST(varint_round_trips_boundary_values) {
  // Every power-of-128 boundary is where the encoded length changes, which is exactly
  // where an off-by-one in the shift or the continuation bit lives.
  std::vector<uint64_t> values = {0, 1, 2, 126, 127, 128, 129, 255, 256, UINT64_MAX};
  for (int k = 7; k <= 63; k += 7) {
    const uint64_t b = uint64_t{1} << k;
    values.push_back(b - 1);
    values.push_back(b);
    values.push_back(b + 1);
  }

  for (uint64_t v : values) {
    TCTX("v=" << v);
    std::vector<uint8_t> buf;
    put_varint(buf, v);
    CHECK_EQ(buf.size(), varint_size(v));
    CHECK_LE(buf.size(), kMaxVarintBytes);

    size_t pos = 0;
    uint64_t got = 0;
    REQUIRE(get_varint(ByteSpan(buf.data(), buf.size()), pos, got));
    CHECK_EQ(got, v);
    CHECK_EQ(pos, buf.size());  // consumed exactly the bytes it wrote
  }
}

TEST(varint_rejects_truncated_and_overlong) {
  // Truncation: every proper prefix of a multi-byte encoding must fail, and must leave
  // pos untouched so a decode loop cannot half-advance over a bad buffer.
  for (uint64_t v : {uint64_t{128}, uint64_t{1} << 35, UINT64_MAX}) {
    std::vector<uint8_t> buf;
    put_varint(buf, v);
    for (size_t cut = 0; cut < buf.size(); cut++) {
      TCTX("v=" << v << " cut=" << cut);
      size_t pos = 0;
      uint64_t got = 0xdeadbeef;
      CHECK(!get_varint(ByteSpan(buf.data(), cut), pos, got));
      CHECK_EQ(pos, size_t{0});  // pos advances only on success
    }
  }

  // Non-canonical spellings. Each of these decodes to a value a naive LEB128 reader
  // would accept, and each is a second encoding of a number that already has one.
  const std::vector<std::vector<uint8_t>> overlong = {
      {0x80, 0x00},                                            // 0, padded to 2 bytes
      {0x80, 0x80, 0x00},                                      // 0, padded to 3
      {0x81, 0x00},                                            // 1, padded
      {0xFF, 0x00},                                            // 127, padded
      {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00},  // 0 in 10 bytes
  };
  for (const auto& b : overlong) {
    TCTX("overlong len=" << b.size());
    size_t pos = 0;
    uint64_t got = 0;
    CHECK(!get_varint(ByteSpan(b.data(), b.size()), pos, got));
    CHECK_EQ(pos, size_t{0});
  }

  // Overflow past 2^64: the 10th byte may only carry bit 63, i.e. it must be 0x01.
  {
    std::vector<uint8_t> too_big(9, 0xFF);
    too_big.push_back(0x02);  // one bit too high
    size_t pos = 0;
    uint64_t got = 0;
    CHECK(!get_varint(ByteSpan(too_big.data(), too_big.size()), pos, got));

    // ...and eleven continuation bytes is not a number at all.
    std::vector<uint8_t> endless(11, 0x80);
    pos = 0;
    CHECK(!get_varint(ByteSpan(endless.data(), endless.size()), pos, got));
  }

  // The legal maximum still decodes, so the rejection above is tight, not blunt.
  {
    std::vector<uint8_t> max_enc(9, 0xFF);
    max_enc.push_back(0x01);
    size_t pos = 0;
    uint64_t got = 0;
    REQUIRE(get_varint(ByteSpan(max_enc.data(), max_enc.size()), pos, got));
    CHECK_EQ(got, UINT64_MAX);
    CHECK_EQ(pos, size_t{10});
  }
}

TEST(varint_random_round_trip_and_stream) {
  // A stream of concatenated varints, decoded back in order: this is how the need-set
  // and the manifest actually use them, and it catches a decoder that reports the right
  // value but the wrong consumed length.
  Rng rng(testing::seed() ^ 0x5a17u);
  for (int iter = 0; iter < 200; iter++) {
    TCTX("iter=" << iter);
    const size_t n = 1 + rng.below(64);
    std::vector<uint64_t> vals(n);
    std::vector<uint8_t> buf;
    for (size_t i = 0; i < n; i++) {
      // Spread across the whole magnitude range rather than clustering on small values,
      // so long encodings get exercised too.
      const uint32_t bits = rng.below(65);
      vals[i] = bits >= 64 ? rng.next() : (rng.next() & ((uint64_t{1} << bits) - 1));
      put_varint(buf, vals[i]);
    }
    size_t pos = 0;
    for (size_t i = 0; i < n; i++) {
      uint64_t got = 0;
      REQUIRE(get_varint(ByteSpan(buf.data(), buf.size()), pos, got));
      CHECK_EQ(got, vals[i]);
    }
    CHECK_EQ(pos, buf.size());
  }
}

// ===================================================================================
// NeedSet
// ===================================================================================

TEST(needset_edge_cases) {
  {
    NeedSet ns;  // empty
    CHECK(ns.empty());
    CHECK_EQ(ns.count(), size_t{0});
    CHECK(ns.encode().empty());
    CHECK(!ns.contains(0));
    auto d = NeedSet::decode(ByteSpan{});
    REQUIRE(d.ok());
    CHECK(d->empty());
  }
  {
    NeedSet ns;  // a single index, added twice: add() deduplicates
    ns.add(7);
    ns.add(7);
    CHECK_EQ(ns.count(), size_t{1});
    CHECK(ns.contains(7));
    CHECK(!ns.contains(6));
    CHECK(!ns.contains(8));
    CHECK_EQ(ns.to_vector().size(), size_t{1});
  }
  {
    // The top of the index space, both ends of it. This case is in the suite because the
    // first version of NeedSet stored runs as (start, length) and got it wrong twice:
    // it rejected the legal index 2^64-1 as an overflow, and its end-of-run arithmetic
    // wrapped to zero, which would have let a hostile encoding place a later run BELOW
    // an earlier one and quietly break the sorted-runs invariant.
    NeedSet ns;
    ns.add(0);
    ns.add(UINT64_MAX);
    CHECK_EQ(ns.count(), size_t{2});
    CHECK(ns.contains(0));
    CHECK(ns.contains(UINT64_MAX));
    CHECK(!ns.contains(UINT64_MAX - 1));
    CHECK(!ns.contains(1));
    const auto enc = ns.encode();  // a local: ns.encode() twice would dangle the first
    auto d = NeedSet::decode(ByteSpan(enc.data(), enc.size()));
    REQUIRE(d.ok());
    CHECK(d->contains(UINT64_MAX));
    CHECK(d->contains(0));
    CHECK(!d->contains(UINT64_MAX - 1));
    CHECK_EQ(d->count(), size_t{2});
    const auto re = d->encode();
    CHECK_EQ(re.size(), enc.size());

    // ...and a run that reaches 2^64-1 must be the last thing in the buffer.
    auto trailing = enc;
    put_varint(trailing, 1);
    put_varint(trailing, 0);
    auto bad = NeedSet::decode(ByteSpan(trailing.data(), trailing.size()));
    CHECK(!bad.ok());
    CHECK_EQ(bad.code(), Err::kMalformed);
  }
  {
    NeedSet ns;  // a single run covering the very top of the space
    ns.add(UINT64_MAX - 1);
    ns.add(UINT64_MAX);
    CHECK_EQ(ns.run_count(), size_t{1});
    CHECK_EQ(ns.count(), size_t{2});
    const auto enc = ns.encode();
    auto d = NeedSet::decode(ByteSpan(enc.data(), enc.size()));
    REQUIRE(d.ok());
    CHECK_EQ(d->count(), size_t{2});
    const auto v = d->to_vector();
    REQUIRE(v.size() == 2);
    CHECK_EQ(v[0], UINT64_MAX - 1);
    CHECK_EQ(v[1], UINT64_MAX);  // to_vector() must terminate at the top of the range
  }
  {
    NeedSet ns;  // out-of-order adds must coalesce into maximal runs
    for (uint64_t i : {5u, 3u, 4u, 9u, 1u, 2u, 10u}) ns.add(i);
    const auto v = ns.to_vector();
    const std::vector<uint64_t> want = {1, 2, 3, 4, 5, 9, 10};
    CHECK_EQ(v.size(), want.size());
    for (size_t i = 0; i < want.size() && i < v.size(); i++) CHECK_EQ(v[i], want[i]);
    CHECK_EQ(ns.run_count(), size_t{2});  // 1..5 and 9..10
  }
}

TEST(needset_round_trip_random_sparse_and_dense) {
  Rng rng(testing::seed() ^ 0x11ee7u);
  for (int iter = 0; iter < 300; iter++) {
    // Alternate the density on purpose: a sparse set exercises the gap varints, a dense
    // one exercises run coalescing, and the two have different failure modes.
    const bool dense = (iter % 2) == 0;
    const uint64_t span = dense ? 400 : 4000000;
    const size_t n = 1 + rng.below(dense ? 300 : 40);
    TCTX("iter=" << iter << " dense=" << (dense ? 1 : 0) << " n=" << n);

    NeedSet ns;
    std::set<uint64_t> oracle;
    for (size_t i = 0; i < n; i++) {
      const uint64_t v = rng.next() % span;
      ns.add(v);
      oracle.insert(v);
    }

    CHECK_EQ(ns.count(), oracle.size());
    const auto enc = ns.encode();
    auto dec = NeedSet::decode(ByteSpan(enc.data(), enc.size()));
    REQUIRE(dec.ok());
    CHECK_EQ(dec->count(), oracle.size());

    const auto v = dec->to_vector();
    REQUIRE(v.size() == oracle.size());
    size_t i = 0;
    for (uint64_t want : oracle) {
      CHECK_EQ(v[i++], want);
      CHECK(dec->contains(want));
    }

    // Re-encoding a decoded set must reproduce the exact bytes. That is the canonical-
    // encoding property: one set, one spelling, so an encoded need-set can be compared
    // or digested and mean what it appears to mean.
    const auto re = dec->encode();
    CHECK_EQ(re.size(), enc.size());
    // Guarded: memcmp(nullptr, nullptr, 0) is UB, and UBSan says so out loud.
    const size_t n_cmp = std::min(re.size(), enc.size());
    if (n_cmp) CHECK(std::memcmp(re.data(), enc.data(), n_cmp) == 0);
  }
}

TEST(needset_long_runs_and_sparse_cost) {
  // SPEC 3.3's claim, asserted and printed: "a handful of bytes to describe millions of
  // chunks it does not need."
  constexpr uint64_t kM = 1000000;

  {  // 1 needed out of 1 000 000
    NeedSet ns;
    ns.add(kM - 1);
    const auto enc = ns.encode();
    std::printf("    note: NEED for 1 of %" PRIu64 " chunks encodes to %zu bytes\n", kM,
                enc.size());
    CHECK_LE(enc.size(), size_t{8});
  }
  {  // 10 scattered singles out of 1 000 000
    NeedSet ns;
    for (int i = 0; i < 10; i++) ns.add(static_cast<uint64_t>(i) * 97391 + 13);
    const auto enc = ns.encode();
    std::printf("    note: NEED for 10 scattered of %" PRIu64 " chunks encodes to %zu bytes\n",
                kM, enc.size());
    CHECK_LE(enc.size(), size_t{64});
  }
  {  // the first-ever replication: every chunk needed -> one run
    NeedSet ns;
    for (uint64_t i = 0; i < kM; i++) ns.add(i);
    const auto enc = ns.encode();
    std::printf("    note: NEED for ALL %" PRIu64 " chunks encodes to %zu bytes (%zu run)\n",
                kM, enc.size(), ns.run_count());
    CHECK_EQ(ns.run_count(), size_t{1});
    CHECK_LE(enc.size(), size_t{8});
    CHECK_EQ(ns.count(), static_cast<size_t>(kM));

    auto dec = NeedSet::decode(ByteSpan(enc.data(), enc.size()));
    REQUIRE(dec.ok());
    CHECK_EQ(dec->count(), static_cast<size_t>(kM));
    CHECK(dec->contains(0));
    CHECK(dec->contains(kM - 1));
    CHECK(!dec->contains(kM));
  }
  {  // one changed file's worth: a contiguous block in the middle
    NeedSet ns;
    for (uint64_t i = 500000; i < 500128; i++) ns.add(i);
    const auto enc = ns.encode();
    std::printf("    note: NEED for a 128-chunk contiguous edit encodes to %zu bytes\n",
                enc.size());
    CHECK_LE(enc.size(), size_t{8});
  }
  {  // the RLE's worst case, measured rather than assumed: maximal scatter
    NeedSet ns;
    for (uint64_t i = 0; i < kM; i += 37) ns.add(i);
    const auto enc = ns.encode();
    const double per_index = static_cast<double>(enc.size()) / static_cast<double>(ns.count());
    std::printf("    note: worst case -- %zu isolated indices over %" PRIu64
                " encodes to %zu bytes (%.2f B/index)\n",
                ns.count(), kM, enc.size(), per_index);
    CHECK_EQ(ns.run_count(), ns.count());  // every index is its own run: no RLE win at all
    // Two bytes per index is the floor of this encoding (one varint gap + one varint
    // length-1), and it must still beat a plain varint list of the same indices, which is
    // what the RLE replaced. If it ever does not, the encoding choice was wrong.
    CHECK_LE(per_index, 2.05);
    size_t plain = 0;
    for (uint64_t v : ns.to_vector()) plain += varint_size(v);
    std::printf("    note: ...vs %zu bytes as a plain varint list (%.2f B/index)\n", plain,
                static_cast<double>(plain) / static_cast<double>(ns.count()));
    CHECK_LT(enc.size(), plain);
  }
}

TEST(needset_decode_rejects_hostile_input) {
  // 1. The allocation bomb S7 exists for: a tiny buffer claiming an astronomical run.
  {
    std::vector<uint8_t> b;
    put_varint(b, 0);            // gap
    put_varint(b, UINT64_MAX - 1);  // runlen-1 -> a run of 2^64-1 indices
    const size_t before = rss_bytes();
    auto d = NeedSet::decode(ByteSpan(b.data(), b.size()));
    const size_t after = rss_bytes();
    CHECK(!d.ok());
    CHECK_EQ(d.code(), Err::kTooLarge);
    std::printf("    note: %zu-byte need-set claiming 2^64 indices -> %s, RSS delta %zd B\n",
                b.size(), to_string(d.code()),
                static_cast<ptrdiff_t>(after) - static_cast<ptrdiff_t>(before));
  }
  // 2. Exactly at the cap is legal; one past it is not. A cap that is off by one is a
  //    cap nobody can reason about.
  {
    std::vector<uint8_t> ok_buf, bad_buf;
    put_varint(ok_buf, 0);
    put_varint(ok_buf, kMaxNeedIndices - 1);
    put_varint(bad_buf, 0);
    put_varint(bad_buf, kMaxNeedIndices);
    auto a = NeedSet::decode(ByteSpan(ok_buf.data(), ok_buf.size()));
    REQUIRE(a.ok());
    CHECK_EQ(static_cast<uint64_t>(a->count()), kMaxNeedIndices);
    auto b = NeedSet::decode(ByteSpan(bad_buf.data(), bad_buf.size()));
    CHECK(!b.ok());
    CHECK_EQ(b.code(), Err::kTooLarge);
  }
  // 3. The cap is on the TOTAL, not per run: many legal runs must still be summed.
  {
    std::vector<uint8_t> b;
    put_varint(b, 0);
    put_varint(b, kMaxNeedIndices - 1);  // exactly the cap
    put_varint(b, 1);                    // a second run, one more index
    put_varint(b, 0);
    auto d = NeedSet::decode(ByteSpan(b.data(), b.size()));
    CHECK(!d.ok());
    CHECK_EQ(d.code(), Err::kTooLarge);
  }
  // 4. Structural malformations, each a distinct way of being not-a-need-set.
  struct Case {
    const char* name;
    std::vector<uint8_t> bytes;
    Err want;
  };
  std::vector<Case> cases;
  {
    std::vector<uint8_t> b;
    put_varint(b, 3);
    cases.push_back({"gap with no run length", b, Err::kMalformed});
  }
  {
    std::vector<uint8_t> b = {0x80};  // a truncated varint
    cases.push_back({"truncated first varint", b, Err::kMalformed});
  }
  {
    std::vector<uint8_t> b;
    put_varint(b, 0);
    put_varint(b, 0);
    put_varint(b, 0);  // gap 0 between run 0 and run 1 -> adjacent, non-maximal
    put_varint(b, 0);
    cases.push_back({"adjacent runs", b, Err::kMalformed});
  }
  {
    std::vector<uint8_t> b;
    put_varint(b, UINT64_MAX);  // start = 2^64-1
    put_varint(b, 1);           // len 2 -> end overflows
    cases.push_back({"end overflows uint64", b, Err::kMalformed});
  }
  {
    std::vector<uint8_t> b;
    put_varint(b, 0);
    put_varint(b, 0);
    b.push_back(0x80);  // a trailing partial pair
    cases.push_back({"trailing garbage", b, Err::kMalformed});
  }
  {
    std::vector<uint8_t> b = {0x80, 0x00, 0x00};  // over-long varint for the gap
    cases.push_back({"non-canonical gap varint", b, Err::kMalformed});
  }
  for (const auto& c : cases) {
    TCTX("case=" << c.name);
    auto d = NeedSet::decode(ByteSpan(c.bytes.data(), c.bytes.size()));
    CHECK(!d.ok());
    CHECK_EQ(d.code(), c.want);
  }
}

TEST(needset_decode_random_buffer_fuzz) {
  // The decoder must never crash and never allocate wildly on arbitrary bytes. Anything
  // it *accepts* must survive a re-encode/re-decode cycle, which is the property that
  // would break if the canonicalization rules and the decoder ever disagreed.
  Rng rng(testing::seed() ^ 0xf0220u);
  const size_t rss_before = rss_bytes();
  size_t accepted = 0;
  constexpr int kIters = 20000;
  for (int iter = 0; iter < kIters; iter++) {
    TCTX("iter=" << iter);
    const size_t n = rng.below(48);
    const auto buf = random_bytes(n, rng);
    auto d = NeedSet::decode(ByteSpan(buf.data(), buf.size()));
    if (!d.ok()) {
      CHECK(d.code() == Err::kMalformed || d.code() == Err::kTooLarge);
      continue;
    }
    accepted++;
    CHECK_LE(static_cast<uint64_t>(d->count()), kMaxNeedIndices);
    const auto re = d->encode();
    CHECK_EQ(re.size(), n);  // canonical: an accepted buffer re-encodes to itself
    const size_t n_cmp = std::min(re.size(), n);
    if (n_cmp) CHECK(std::memcmp(re.data(), buf.data(), n_cmp) == 0);
  }
  const size_t rss_after = rss_bytes();
  std::printf("    note: %d random need-set buffers, %zu accepted, RSS delta %zd B\n",
              kIters, accepted,
              static_cast<ptrdiff_t>(rss_after) - static_cast<ptrdiff_t>(rss_before));
  CHECK_LT(static_cast<ptrdiff_t>(rss_after) - static_cast<ptrdiff_t>(rss_before),
           ptrdiff_t{64} << 20);
}

// ===================================================================================
// Frame round trips
// ===================================================================================

namespace {

// One write + one read over a fresh pipe, with every field compared. Returns false on a
// hard failure so callers can bail rather than dereference a missing frame.
bool round_trip_once(FrameType t, uint64_t seq, const std::vector<uint8_t>& payload,
                     uint8_t flags, uint32_t raw_len, size_t chunk_limit) {
  Pipe p(chunk_limit);
  FrameWriter w(*p.tx);
  auto wr = w.write(t, seq, ByteSpan(payload.data(), payload.size()), flags, raw_len);
  if (!wr.ok()) {
    ::testing::fail(__FILE__, __LINE__, "write failed: " + wr.error().message());
    return false;
  }
  CHECK_EQ(w.frames_written(), uint64_t{1});
  p.tx->close();

  FrameReader r(*p.rx);
  auto got = r.next();
  if (!got.ok()) {
    ::testing::fail(__FILE__, __LINE__, "read failed: " + got.error().message());
    return false;
  }
  CHECK_EQ(r.frames_read(), uint64_t{1});
  CHECK_EQ(static_cast<int>(got->type), static_cast<int>(t));
  CHECK_EQ(got->flags, flags);
  CHECK_EQ(got->seq, seq);
  CHECK_EQ(got->payload.size(), payload.size());
  if (got->payload.size() == payload.size() && !payload.empty()) {
    CHECK(std::memcmp(got->payload.data(), payload.data(), payload.size()) == 0);
  }
  // raw_len is normalized by the reader: an uncompressed frame always reports its own
  // payload length, whatever the caller passed in.
  const uint32_t want_raw =
      (flags & kFlagCompressed) ? raw_len : static_cast<uint32_t>(payload.size());
  CHECK_EQ(got->raw_len, want_raw);

  // After the single frame, a clean end-of-stream -- not a short read, not a reset.
  auto eof = r.next();
  CHECK(!eof.ok());
  CHECK_EQ(eof.code(), Err::kClosed);
  return true;
}

}  // namespace

TEST(frame_round_trip_every_type_and_size) {
  Rng rng(testing::seed() ^ 0xf12a3u);
  const size_t sizes[] = {0, 1, 31, 32, 33, 4096, kMaxFrame - 1, kMaxFrame};

  for (FrameType t : kAllTypes) {
    for (size_t sz : sizes) {
      TCTX("type=" << frame_type_name(t) << " size=" << sz);
      const auto payload = random_bytes(sz, rng);
      // seq is only meaningful for CHUNKS (SPEC 3.2), but the codec must carry any
      // 64-bit value on any type -- including the boundary values where a sign-extension
      // or a truncated-to-32-bit bug would show up.
      const uint64_t seq = (sz % 3 == 0) ? 0 : (sz % 3 == 1 ? UINT64_MAX : rng.next());
      if (!round_trip_once(t, seq, payload, 0, 0, 0)) return;
    }
  }
}

TEST(frame_short_transfer_round_trip) {
  // SPEC 2.5: a 4 MiB send() moved 6 144 bytes. Re-running the round trips through a
  // transport that refuses to move more than N bytes per call is the only way the
  // write_all/read_exact loops inside the codec are actually exercised.
  Rng rng(testing::seed() ^ 0x50047u);
  const size_t limits[] = {1, 3, 7, 1000};
  const size_t small_sizes[] = {0, 1, 31, 32, 33, 4096};

  for (size_t limit : limits) {
    size_t ti = 0;
    for (size_t sz : small_sizes) {
      const FrameType t = kAllTypes[ti++ % (sizeof(kAllTypes) / sizeof(kAllTypes[0]))];
      TCTX("limit=" << limit << " type=" << frame_type_name(t) << " size=" << sz);
      const auto payload = random_bytes(sz, rng);
      if (!round_trip_once(t, rng.next(), payload, 0, 0, limit)) return;
    }
  }

  // A full-size frame through the coarsest limit, so the loop runs ~1 049 times on a
  // payload at the hard ceiling. (The 1-byte limit is deliberately not used here: it
  // would be a million mutex round trips per direction and would say nothing the smaller
  // sizes have not already said.)
  {
    TCTX("limit=1000 size=kMaxFrame");
    const auto payload = random_bytes(kMaxFrame, rng);
    if (!round_trip_once(FrameType::kChunks, 42, payload, 0, 0, 1000)) return;
  }
  std::printf("    note: short-transfer round trips passed at chunk limits 1/3/7/1000\n");
}

TEST(frame_many_frames_in_sequence) {
  // Frames must be self-delimiting: a reader that mis-computes a length by one byte
  // still passes a single-frame test and desynchronizes on frame 2.
  Rng rng(testing::seed() ^ 0x5e900u);
  Pipe p(7);  // a short-transferring transport, to combine the two hazards
  FrameWriter w(*p.tx);

  std::vector<std::vector<uint8_t>> sent;
  constexpr int kN = 200;
  for (int i = 0; i < kN; i++) {
    auto payload = random_bytes(rng.below(300), rng);
    const FrameType t = kAllTypes[static_cast<size_t>(i) % 13];
    auto wr = w.write(t, static_cast<uint64_t>(i),
                      ByteSpan(payload.data(), payload.size()));
    REQUIRE(wr.ok());
    sent.push_back(std::move(payload));
  }
  p.tx->close();

  FrameReader r(*p.rx);
  for (int i = 0; i < kN; i++) {
    TCTX("frame=" << i);
    auto got = r.next();
    REQUIRE(got.ok());
    CHECK_EQ(got->seq, static_cast<uint64_t>(i));
    CHECK_EQ(static_cast<int>(got->type), static_cast<int>(kAllTypes[static_cast<size_t>(i) % 13]));
    CHECK_EQ(got->payload.size(), sent[static_cast<size_t>(i)].size());
  }
  CHECK_EQ(r.frames_read(), static_cast<uint64_t>(kN));
  CHECK_EQ(w.frames_written(), static_cast<uint64_t>(kN));
  auto eof = r.next();
  CHECK_EQ(eof.code(), Err::kClosed);
}

TEST(frame_compressed_flag_and_raw_len_rule) {
  Rng rng(testing::seed() ^ 0xc0b0u);
  // A legal compressed frame: 1 000 wire bytes claiming to expand to 4 000.
  {
    const auto payload = random_bytes(1000, rng);
    if (!round_trip_once(FrameType::kChunks, 9, payload, kFlagCompressed, 4000, 0)) return;
  }
  // raw_len == wire_len is legal for a compressed frame (see the rule's justification in
  // frame.h: > would bake the compressor's tie-break into the framing layer).
  {
    const auto payload = random_bytes(64, rng);
    if (!round_trip_once(FrameType::kChunks, 10, payload, kFlagCompressed, 64, 0)) return;
  }
  // The writer refuses to produce the malformed shape at all.
  {
    Pipe p;
    FrameWriter w(*p.tx);
    std::vector<uint8_t> payload(100, 0xAB);
    auto wr = w.write(FrameType::kChunks, 1, ByteSpan(payload.data(), payload.size()),
                      kFlagCompressed, 99);
    CHECK(!wr.ok());
    CHECK_EQ(wr.code(), Err::kInvalidArgument);

    auto wr2 = w.write(FrameType::kChunks, 1, ByteSpan(payload.data(), payload.size()), 0, 55);
    CHECK(!wr2.ok());
    CHECK_EQ(wr2.code(), Err::kInvalidArgument);

    auto wr3 = w.write(FrameType::kChunks, 1, ByteSpan(payload.data(), payload.size()),
                       kUndefinedFlagBit);  // a bit this protocol version does not define
    CHECK(!wr3.ok());
    CHECK_EQ(wr3.code(), Err::kInvalidArgument);

    std::vector<uint8_t> big(kMaxFrame + 1, 0);
    auto wr4 = w.write(FrameType::kChunks, 1, ByteSpan(big.data(), big.size()));
    CHECK(!wr4.ok());
    CHECK_EQ(wr4.code(), Err::kTooLarge);

    CHECK_EQ(w.frames_written(), uint64_t{0});  // nothing partial reached the wire
  }
}

// ===================================================================================
// Hostile frames -- SPEC S7
// ===================================================================================

TEST(frame_rejects_giant_wire_len_without_allocating) {
  using namespace frame_detail;
  // The attack S7 names: a valid, CRC-correct header whose wire_len is 4 GiB - 1.
  // A reader that trusts the length before range-checking it allocates 4 GiB here.
  uint8_t h[32];
  encode_header(h, static_cast<uint8_t>(FrameType::kChunks), 0, 0xFFFFFFFFu, 0, 1, 0);

  Pipe p;
  auto wr = write_all(*p.tx, ByteSpan(h, sizeof(h)));
  REQUIRE(wr.ok());
  p.tx->close();

  FrameReader r(*p.rx);
  auto got = r.next();
  CHECK(!got.ok());
  CHECK_EQ(got.code(), Err::kTooLarge);

  // The load-bearing proof that nothing was allocated: the reader consumed exactly the
  // 32 header bytes and never asked the transport for the payload it was promised. An
  // implementation that allocated first and range-checked second would have tried.
  CHECK_EQ(p.rx->bytes_in(), uint64_t{32});

  // Same claim from the other direction, over enough iterations that a 4 GiB (or even a
  // 4 MiB) allocation per frame would be unmissable in RSS.
  const size_t before = rss_bytes();
  for (int i = 0; i < 1000; i++) {
    TCTX("iter=" << i);
    uint8_t hh[32];
    // Sweep the top of the 32-bit range and the region just above kMaxFrame, which is
    // where an off-by-one in the range check would live.
    const uint32_t wl = (i % 2) ? (0xFFFFFFFFu - static_cast<uint32_t>(i))
                                : (kMaxFrame + 1 + static_cast<uint32_t>(i));
    encode_header(hh, static_cast<uint8_t>(FrameType::kManifest), 0, wl, 0, 0, 0);
    auto res = read_one(ByteSpan(hh, sizeof(hh)));
    CHECK(!res.ok());
    CHECK_EQ(res.code(), Err::kTooLarge);
  }
  const size_t after = rss_bytes();
  std::printf("    note: 1000 frames claiming up to 4 GiB -> kTooLarge, RSS delta %zd B\n",
              static_cast<ptrdiff_t>(after) - static_cast<ptrdiff_t>(before));
  CHECK_LT(static_cast<ptrdiff_t>(after) - static_cast<ptrdiff_t>(before), ptrdiff_t{32} << 20);

  // kMaxFrame itself is legal, one byte over is not. Asserted together so the boundary
  // cannot silently drift to "off by one in the safe direction" and stay untested.
  {
    uint8_t ok_h[32];
    encode_header(ok_h, static_cast<uint8_t>(FrameType::kChunks), 0, kMaxFrame,
                  kMaxFrame, 0, 0);
    auto res = read_one(ByteSpan(ok_h, sizeof(ok_h)));
    CHECK(!res.ok());
    CHECK_EQ(res.code(), Err::kShortRead);  // the length is accepted; the payload is absent

    uint8_t bad_h[32];
    encode_header(bad_h, static_cast<uint8_t>(FrameType::kChunks), 0, kMaxFrame + 1, 0, 0, 0);
    auto res2 = read_one(ByteSpan(bad_h, sizeof(bad_h)));
    CHECK_EQ(res2.code(), Err::kTooLarge);

    uint8_t bad_raw[32];  // raw_len over the cap, wire_len fine
    encode_header(bad_raw, static_cast<uint8_t>(FrameType::kChunks), kFlagCompressed, 4,
                  kMaxFrame + 1, 0, 0);
    auto res3 = read_one(ByteSpan(bad_raw, sizeof(bad_raw)));
    CHECK_EQ(res3.code(), Err::kTooLarge);
  }
}

TEST(frame_header_bitflip_fuzz) {
  // Every single-bit mutation of every header byte, for several payload shapes. The
  // header CRC should catch essentially all of them; what matters is that NONE produces
  // a crash, a hang, or a success.
  Rng rng(testing::seed() ^ 0xb17fu);
  const size_t sizes[] = {0, 1, 33, 4096};
  int by_code[64] = {0};
  int total = 0;

  for (size_t sz : sizes) {
    const auto payload = random_bytes(sz, rng);
    const auto image = serialize_frame(FrameType::kChunks, 0x0123456789abcdefull,
                                       ByteSpan(payload.data(), payload.size()));
    REQUIRE(image.size() == 32 + sz);

    for (size_t byte = 0; byte < 32; byte++) {
      for (int bit = 0; bit < 8; bit++) {
        TCTX("size=" << sz << " byte=" << byte << " bit=" << bit);
        auto mutated = image;
        mutated[byte] ^= static_cast<uint8_t>(1u << bit);
        auto got = read_one(ByteSpan(mutated.data(), mutated.size()));
        CHECK(!got.ok());
        if (!got.ok()) {
          const Err c = got.code();
          CHECK(c == Err::kBadHeaderCrc || c == Err::kBadMagic || c == Err::kTooLarge ||
                c == Err::kMalformed);
          by_code[static_cast<int>(c) & 63]++;
          total++;
        }
      }
    }
  }
  std::printf("    note: %d header bit flips, all rejected; bad-header-crc=%d "
              "bad-magic=%d too-large=%d malformed=%d\n",
              total, by_code[static_cast<int>(Err::kBadHeaderCrc) & 63],
              by_code[static_cast<int>(Err::kBadMagic) & 63],
              by_code[static_cast<int>(Err::kTooLarge) & 63],
              by_code[static_cast<int>(Err::kMalformed) & 63]);
  // A flipped header bit changes the CRC coverage in all 32 bytes except the CRC field
  // itself, where it changes the expected value -- so every case should be kBadHeaderCrc.
  // Asserting that explicitly is what would catch a reader that read a field first.
  CHECK_EQ(by_code[static_cast<int>(Err::kBadHeaderCrc) & 63], total);
}

TEST(frame_rejects_crafted_bad_header_fields) {
  using namespace frame_detail;
  // The mutations the CRC cannot catch, because they are self-consistent: a hostile peer
  // recomputes header_crc after choosing its fields. This is the real threat model --
  // the bit-flip test above is bit rot, this one is an adversary.
  struct Case {
    const char* name;
    uint8_t type;
    uint8_t flags;
    uint32_t wire_len;
    uint32_t raw_len;
    uint16_t reserved;
    uint32_t magic;
    Err want;
  };
  const Case cases[] = {
      {"unknown type 0", 0, 0, 0, 0, 0, kFrameMagic, Err::kMalformed},
      {"unknown type 14", 14, 0, 0, 0, 0, kFrameMagic, Err::kMalformed},
      {"unknown type 255", 255, 0, 0, 0, 0, kFrameMagic, Err::kMalformed},
      {"undefined flag bit", 8, kUndefinedFlagBit, 0, 0, 0, kFrameMagic, Err::kMalformed},
      {"all flag bits", 8, 0xFF, 0, 0, 0, kFrameMagic, Err::kMalformed},
      {"reserved nonzero", 8, 0, 0, 0, 1, kFrameMagic, Err::kMalformed},
      {"reserved 0xFFFF", 8, 0, 0, 0, 0xFFFF, kFrameMagic, Err::kMalformed},
      {"wrong magic", 8, 0, 0, 0, 0, 0xDEADBEEFu, Err::kBadMagic},
      {"magic byte-swapped", 8, 0, 0, 0, 0, __builtin_bswap32(kFrameMagic), Err::kBadMagic},
      {"wire_len over cap", 8, 0, kMaxFrame + 1, 0, 0, kFrameMagic, Err::kTooLarge},
      {"raw_len over cap", 8, 0, 0, kMaxFrame + 1, 0, kFrameMagic, Err::kTooLarge},
      // The compressed-frame bound attack: 100 wire bytes claiming to expand to 50.
      {"compressed shrinks", 8, kFlagCompressed, 100, 50, 0, kFrameMagic, Err::kMalformed},
      {"compressed raw_len 0", 8, kFlagCompressed, 100, 0, 0, kFrameMagic, Err::kMalformed},
      {"uncompressed raw_len mismatch", 8, 0, 100, 99, 0, kFrameMagic, Err::kMalformed},
  };

  for (const Case& c : cases) {
    TCTX("case=" << c.name);
    uint8_t h[32];
    // Built by hand rather than through encode_header(), because these cases need fields
    // encode_header() would refuse to produce -- then re-CRC'd so the header is
    // internally consistent and only the semantic check can reject it.
    put_u32_le(h + kOffMagic, c.magic);
    h[kOffType] = c.type;
    h[kOffFlags] = c.flags;
    put_u16_le(h + kOffReserved, c.reserved);
    put_u32_le(h + kOffWireLen, c.wire_len);
    put_u32_le(h + kOffRawLen, c.raw_len);
    put_u64_le(h + kOffSeq, 0);
    put_u32_le(h + kOffPayloadCrc, 0);
    put_u32_le(h + kOffHeaderCrc, crc32c(ByteSpan(h, kHeaderCrcCoverage)));

    auto got = read_one(ByteSpan(h, sizeof(h)));
    CHECK(!got.ok());
    CHECK_EQ(got.code(), c.want);
  }
}

TEST(frame_payload_bitflip_is_bad_payload_crc) {
  Rng rng(testing::seed() ^ 0xba71u);
  const size_t sizes[] = {1, 32, 4096};
  for (size_t sz : sizes) {
    const auto payload = random_bytes(sz, rng);
    const auto image = serialize_frame(FrameType::kManifest, 5,
                                       ByteSpan(payload.data(), payload.size()));
    REQUIRE(image.size() == 32 + sz);
    // Sample the payload rather than sweeping all 4096*8 bits: CRC32C detects every
    // single-bit error by construction, so the sweep would restate the same fact 32 768
    // times and slow the ASan build for nothing.
    for (int trial = 0; trial < 64; trial++) {
      const size_t byte = 32 + (rng.next() % sz);
      const int bit = static_cast<int>(rng.below(8));
      TCTX("size=" << sz << " byte=" << byte << " bit=" << bit);
      auto mutated = image;
      mutated[byte] ^= static_cast<uint8_t>(1u << bit);
      auto got = read_one(ByteSpan(mutated.data(), mutated.size()));
      CHECK(!got.ok());
      CHECK_EQ(got.code(), Err::kBadPayloadCrc);
    }
  }
}

TEST(frame_truncation_is_short_read) {
  Rng rng(testing::seed() ^ 0x71c0cu);
  const auto payload = random_bytes(500, rng);
  const auto image =
      serialize_frame(FrameType::kChunks, 77, ByteSpan(payload.data(), payload.size()));
  REQUIRE(image.size() == 532);

  // Cut 0 is a clean end-of-stream between frames: kClosed, and that distinction is the
  // whole point (SPEC 3.7). Every other cut lands mid-structure: kShortRead.
  for (size_t cut = 0; cut < image.size(); cut++) {
    TCTX("cut=" << cut);
    auto got = read_one(ByteSpan(image.data(), cut));
    CHECK(!got.ok());
    CHECK_EQ(got.code(), cut == 0 ? Err::kClosed : Err::kShortRead);
  }

  // Cut exactly on the header/payload boundary (32 bytes, no payload) is the case a
  // naive reader reports as kClosed, because read_exact for the payload sees a clean EOF
  // at offset 0. It is not a clean EOF: the header already promised those bytes.
  {
    auto got = read_one(ByteSpan(image.data(), 32));
    CHECK_EQ(got.code(), Err::kShortRead);
  }
  // Same again through a short-transferring transport, where the truncation is
  // discovered on a later loop iteration rather than the first.
  for (size_t cut : {size_t{5}, size_t{31}, size_t{32}, size_t{33}, size_t{531}}) {
    TCTX("cut=" << cut << " limit=3");
    auto got = read_one(ByteSpan(image.data(), cut), 3);
    CHECK_EQ(got.code(), Err::kShortRead);
  }
}

TEST(frame_clean_close_and_abrupt_close_are_distinguishable) {
  // SPEC 2.5 measured that an orderly close makes recv() return 0 while an abortive one
  // returns ECONNRESET, and SPEC 3.7's resume logic branches on it. If these two
  // collapsed into one code, a killed peer would look like a finished one and a
  // truncated transfer would be committed as complete.
  Rng rng(testing::seed() ^ 0xc105eu);
  const auto payload = random_bytes(128, rng);

  {  // orderly: BYE, then close() -> the next read is kClosed
    Pipe p;
    FrameWriter w(*p.tx);
    REQUIRE(w.write(FrameType::kBye, 0, ByteSpan(payload.data(), payload.size())).ok());
    FrameReader r(*p.rx);
    auto f = r.next();
    REQUIRE(f.ok());
    CHECK_EQ(static_cast<int>(f->type), static_cast<int>(FrameType::kBye));
    p.tx->close();
    auto eof = r.next();
    CHECK(!eof.ok());
    CHECK_EQ(eof.code(), Err::kClosed);
  }
  {  // abortive: the peer dies between frames -> kReset
    Pipe p;
    FrameWriter w(*p.tx);
    REQUIRE(w.write(FrameType::kChunks, 1, ByteSpan(payload.data(), payload.size())).ok());
    FrameReader r(*p.rx);
    auto f = r.next();
    REQUIRE(f.ok());
    p.tx->close_abruptly();
    auto dead = r.next();
    CHECK(!dead.ok());
    CHECK_EQ(dead.code(), Err::kReset);
  }
  {  // abortive mid-stream: an RST discards buffered data, exactly like the kernel
    Pipe p;
    FrameWriter w(*p.tx);
    REQUIRE(w.write(FrameType::kChunks, 2, ByteSpan(payload.data(), payload.size())).ok());
    p.tx->close_abruptly();
    FrameReader r(*p.rx);
    auto dead = r.next();
    CHECK(!dead.ok());
    CHECK_EQ(dead.code(), Err::kReset);
    CHECK_EQ(r.frames_read(), uint64_t{0});
  }
}

TEST(frame_random_buffer_fuzz) {
  // Thousands of arbitrary byte buffers into FrameReader. The requirement is absolute:
  // never a crash, never a hang, always a typed error -- and under ASan+UBSan, never an
  // out-of-bounds read or an overflow either.
  //
  // Three populations, because a fuzzer that only produces noise measures the first rung
  // of the validation ladder eight thousand times and the rest never:
  //   (a) uniform noise -- almost all of it dies on the header CRC;
  //   (b) a valid frame with bytes corrupted -- also mostly the header CRC, plus the
  //       payload CRC and the truncation paths;
  //   (c) a valid frame corrupted AND RE-CRC'd, which is what an actual adversary does.
  //       Only (c) reaches the magic / reserved / type / flags / length / raw_len rungs,
  //       so without it those checks would be exercised solely by the hand-written cases
  //       and nothing would ever hit them in a combination nobody thought of.
  Rng rng(testing::seed() ^ 0xfa22u);
  constexpr int kIters = 8000;
  size_t accepted = 0;
  int by_code[64] = {0};
  const size_t rss_before = rss_bytes();

  const auto base_payload = random_bytes(64, rng);
  const auto base = serialize_frame(FrameType::kChunks, 1234,
                                    ByteSpan(base_payload.data(), base_payload.size()));
  REQUIRE(!base.empty());

  for (int iter = 0; iter < kIters; iter++) {
    TCTX("iter=" << iter);
    std::vector<uint8_t> buf;
    const int population = iter % 3;
    if (population == 0) {
      buf = random_bytes(rng.below(80), rng);
    } else {
      buf = base;
      const int mutations = 1 + static_cast<int>(rng.below(6));
      for (int m = 0; m < mutations; m++) {
        // Population (c) aims its mutations at the header, since that is where the
        // interesting rungs are; population (b) hits the whole image.
        const size_t at = (population == 2) ? (rng.next() % 32) : (rng.next() % buf.size());
        buf[at] = rng.byte();
      }
      if (population == 2) {
        // The adversary's move: make the header internally consistent again, so every
        // check downstream of the CRC has to stand on its own.
        frame_detail::put_u32_le(buf.data() + frame_detail::kOffHeaderCrc,
                                 crc32c(ByteSpan(buf.data(), kHeaderCrcCoverage)));
      }
      // Sometimes truncate or extend, so length handling is fuzzed too.
      const uint32_t shape = rng.below(4);
      if (shape == 0 && buf.size() > 1) buf.resize(rng.next() % buf.size());
      if (shape == 1) {
        const auto tail = random_bytes(rng.below(40), rng);
        buf.insert(buf.end(), tail.begin(), tail.end());
      }
    }

    auto got = read_one(ByteSpan(buf.data(), buf.size()));
    if (got.ok()) {
      accepted++;
      // An accepted frame must be internally consistent: within the cap, and with the
      // raw_len rule satisfied. This is what catches a validation ladder with a rung
      // that is reachable but never actually enforced.
      CHECK_LE(got->payload.size(), size_t{kMaxFrame});
      CHECK_LE(got->raw_len, kMaxFrame);
      if (got->compressed()) {
        CHECK_GE(got->raw_len, static_cast<uint32_t>(got->payload.size()));
      } else {
        CHECK_EQ(got->raw_len, static_cast<uint32_t>(got->payload.size()));
      }
      CHECK(is_known_frame_type(static_cast<uint8_t>(got->type)));
    } else {
      CHECK(is_clean_frame_error(got.code()));
      by_code[static_cast<int>(got.code()) & 63]++;
    }
  }
  const size_t rss_after = rss_bytes();
  std::printf("    note: %d fuzzed frame buffers, %zu accepted; short-read=%d "
              "bad-header-crc=%d bad-magic=%d bad-payload-crc=%d too-large=%d "
              "malformed=%d closed=%d\n",
              kIters, accepted, by_code[static_cast<int>(Err::kShortRead) & 63],
              by_code[static_cast<int>(Err::kBadHeaderCrc) & 63],
              by_code[static_cast<int>(Err::kBadMagic) & 63],
              by_code[static_cast<int>(Err::kBadPayloadCrc) & 63],
              by_code[static_cast<int>(Err::kTooLarge) & 63],
              by_code[static_cast<int>(Err::kMalformed) & 63],
              by_code[static_cast<int>(Err::kClosed) & 63]);
  std::printf("    note: fuzz RSS delta %zd B\n",
              static_cast<ptrdiff_t>(rss_after) - static_cast<ptrdiff_t>(rss_before));
  CHECK_LT(static_cast<ptrdiff_t>(rss_after) - static_cast<ptrdiff_t>(rss_before),
           ptrdiff_t{64} << 20);
}

TEST(frame_needset_travels_as_a_frame) {
  // The integration T2 actually owes T7: a NEED reply is a NeedSet encoded into a frame
  // payload. Testing the two codecs only in isolation would leave the seam untested, and
  // the seam is where a length is most often computed twice and agreed on once.
  Rng rng(testing::seed() ^ 0x11ee6u);
  for (int iter = 0; iter < 100; iter++) {
    TCTX("iter=" << iter);
    NeedSet ns;
    std::set<uint64_t> oracle;
    const size_t n = 1 + rng.below(200);
    for (size_t i = 0; i < n; i++) {
      const uint64_t v = rng.next() % 100000;
      ns.add(v);
      oracle.insert(v);
    }
    const auto enc = ns.encode();

    Pipe p(rng.below(2) ? 5 : 0);
    FrameWriter w(*p.tx);
    REQUIRE(w.write(FrameType::kNeed, 0, ByteSpan(enc.data(), enc.size())).ok());
    p.tx->close();

    FrameReader r(*p.rx);
    auto f = r.next();
    REQUIRE(f.ok());
    CHECK_EQ(static_cast<int>(f->type), static_cast<int>(FrameType::kNeed));
    auto dec = NeedSet::decode(ByteSpan(f->payload.data(), f->payload.size()));
    REQUIRE(dec.ok());
    CHECK_EQ(dec->count(), oracle.size());
    for (uint64_t want : oracle) CHECK(dec->contains(want));
  }
}

// ===================================================================================
// Adversarial review pass (T2 verification)
//
// The tests above were written alongside the implementation, which is the failure mode
// SPEC 6 warns about: a suite that agrees with the code it was written next to. These
// were written by attacking the headers instead, and the first two of them failed
// against the implementation as delivered.
// ===================================================================================

// A need-set whose decoded state can be described without reaching into the class:
// the four public numbers that must agree with each other no matter what bytes arrived.
namespace {

// Every invariant a decoded NeedSet must satisfy, checked in one place so every hostile
// input in this section is held to the same standard (the "single oracle" idea of SPEC
// R3.4, applied to a decoder instead of to a store).
void check_needset_invariants(const NeedSet& ns, ByteSpan source_bytes) {
  const size_t n = ns.count();
  const size_t runs = ns.run_count();

  // The cap is the entire reason decode() has a policy error code. If it can be walked
  // past, every caller that sizes an allocation from count() is holding a number the
  // peer chose (SPEC S7, S12).
  CHECK_LE(static_cast<uint64_t>(n), kMaxNeedIndices);

  // count()==0 and empty() are two spellings of the same fact. They can only disagree if
  // the sum in count() wrapped, which is exactly what an over-large run does.
  CHECK_EQ(n == 0, ns.empty());

  // Every run holds at least one index, so the total can never be below the run count.
  CHECK_GE(n, runs);

  // Canonicality: an accepted buffer must re-encode to itself, bit for bit. If it does
  // not, two byte strings mean one set and a digest over an encoded need-set is not a
  // digest over the set.
  const auto re = ns.encode();
  CHECK_EQ(re.size(), source_bytes.size());
  if (re.size() == source_bytes.size() && !re.empty()) {
    CHECK(std::memcmp(re.data(), source_bytes.data(), re.size()) == 0);
  }

  // Materializing is only safe to attempt when the cap actually held; doing it for a
  // large-but-legal set would allocate 128 MiB and prove nothing new. The `n >= runs`
  // half of the guard is not cosmetic: if count() has wrapped, to_vector() walks the
  // whole 2^64 index space and the OOM killer ends the test run before it can report
  // which assertion failed. A broken invariant must be reported, not acted on.
  if (n <= 4096 && n >= runs) {
    const auto v = ns.to_vector();
    CHECK_EQ(v.size(), n);
    for (size_t i = 1; i < v.size(); i++) CHECK_LT(v[i - 1], v[i]);  // strictly ascending
    for (uint64_t idx : v) CHECK(ns.contains(idx));
  }
}

}  // namespace

TEST(needset_decode_rejects_a_run_over_the_whole_index_space) {
  // The one value the original hostile-input test missed. It used UINT64_MAX-1 as the
  // run length, for which len = last-start+1 = 2^64-1 and the cap check works. At
  // exactly UINT64_MAX the same expression is 2^64, which wraps to 0 in uint64 -- and a
  // length of "0" is trivially under any cap, so the run covering all 2^64 indices is
  // waved through. Eleven bytes.
  std::vector<uint8_t> b;
  put_varint(b, 0);           // gap -> start = 0
  put_varint(b, UINT64_MAX);  // runlen-1 -> [0, 2^64-1], the entire index space
  CHECK_EQ(b.size(), size_t{11});

  auto d = NeedSet::decode(ByteSpan(b.data(), b.size()));
  CHECK(!d.ok());
  CHECK_EQ(d.code(), Err::kTooLarge);
  if (d.ok()) {
    // Report what got through, so a regression names the damage rather than just failing.
    std::printf("    note: ACCEPTED whole-space run: empty=%d run_count=%zu count=%zu\n",
                static_cast<int>(d->empty()), d->run_count(), d->count());
    check_needset_invariants(*d, ByteSpan(b.data(), b.size()));
  }

  // The neighbours, so the fix is a fix and not a special case: one index short of the
  // whole space is still rejected, and a legal run at the very top still decodes.
  {
    std::vector<uint8_t> c;
    put_varint(c, 0);
    put_varint(c, UINT64_MAX - 1);
    auto r = NeedSet::decode(ByteSpan(c.data(), c.size()));
    CHECK(!r.ok());
    CHECK_EQ(r.code(), Err::kTooLarge);
  }
  {
    std::vector<uint8_t> c;
    put_varint(c, UINT64_MAX - 1);  // start = 2^64-2
    put_varint(c, 1);               // -> [2^64-2, 2^64-1], two indices, legal
    auto r = NeedSet::decode(ByteSpan(c.data(), c.size()));
    REQUIRE(r.ok());
    CHECK_EQ(r->count(), size_t{2});
    check_needset_invariants(*r, ByteSpan(c.data(), c.size()));
  }
  // A start of 0 with a run length of exactly the cap is the legal maximum, and it must
  // still be legal -- the fix must not shave an index off the boundary.
  {
    std::vector<uint8_t> c;
    put_varint(c, 0);
    put_varint(c, kMaxNeedIndices - 1);
    auto r = NeedSet::decode(ByteSpan(c.data(), c.size()));
    REQUIRE(r.ok());
    CHECK_EQ(static_cast<uint64_t>(r->count()), kMaxNeedIndices);
  }
}

TEST(needset_structured_hostile_fuzz) {
  // Uniform random bytes (the fuzz test above) almost never produce a 10-byte varint, so
  // the arithmetic at the top of the index space -- which is where every overflow in this
  // decoder lives -- was being fuzzed at a rate of approximately never. This fuzzer
  // builds *well-formed* varint pairs out of deliberately hostile magnitudes instead, so
  // every iteration reaches the range arithmetic rather than dying at the varint parser.
  const uint64_t interesting[] = {
      0,
      1,
      2,
      127,
      128,
      kMaxNeedIndices - 2,
      kMaxNeedIndices - 1,
      kMaxNeedIndices,
      kMaxNeedIndices + 1,
      uint64_t{1} << 32,
      uint64_t{1} << 63,
      UINT64_MAX - 2,
      UINT64_MAX - 1,
      UINT64_MAX,
  };
  constexpr size_t kN = sizeof(interesting) / sizeof(interesting[0]);

  size_t accepted = 0, rejected = 0;

  // One pair, exhaustively: every (gap, runlen-1) combination of the magnitudes above.
  for (size_t g = 0; g < kN; g++) {
    for (size_t l = 0; l < kN; l++) {
      TCTX("pairs=1 gap=" << interesting[g] << " lenm1=" << interesting[l]);
      std::vector<uint8_t> b;
      put_varint(b, interesting[g]);
      put_varint(b, interesting[l]);
      auto d = NeedSet::decode(ByteSpan(b.data(), b.size()));
      if (!d.ok()) {
        CHECK(d.code() == Err::kMalformed || d.code() == Err::kTooLarge);
        rejected++;
        continue;
      }
      accepted++;
      check_needset_invariants(*d, ByteSpan(b.data(), b.size()));
    }
  }

  // Two and three pairs, randomized over the same magnitudes, so run-to-run interactions
  // (the running total, next_free, the exhausted flag) are exercised as well.
  Rng rng(testing::seed() ^ 0xd15ea5eull);
  for (int iter = 0; iter < 20000; iter++) {
    const size_t pairs = 2 + rng.below(2);
    TCTX("iter=" << iter << " pairs=" << pairs);
    std::vector<uint8_t> b;
    for (size_t i = 0; i < pairs; i++) {
      put_varint(b, interesting[rng.below(kN)]);
      put_varint(b, interesting[rng.below(kN)]);
    }
    auto d = NeedSet::decode(ByteSpan(b.data(), b.size()));
    if (!d.ok()) {
      CHECK(d.code() == Err::kMalformed || d.code() == Err::kTooLarge);
      rejected++;
      continue;
    }
    accepted++;
    check_needset_invariants(*d, ByteSpan(b.data(), b.size()));
  }
  std::printf("    note: structured need-set fuzz: %zu accepted, %zu rejected\n", accepted,
              rejected);
}

TEST(needset_at_the_frame_ceiling_stays_bounded) {
  // needset.h derives kMaxNeedIndices partly from the claim that "2 bytes is the smallest
  // possible run, so a full frame can carry at most ~512 Ki runs". That is an arithmetic
  // claim about the decoder's worst-case allocation, and it is load-bearing: run storage
  // is the one thing decode() sizes from the input, so if the claim is wrong the memory
  // bound in SPEC S10 is wrong with it. Asserted here rather than believed.
  //
  // The maximally run-dense encoding: every pair is (gap=1, runlen-1=0), one byte each,
  // producing isolated indices 1, 3, 5, ... -- the densest a canonical need-set can be in
  // runs per byte, since gap 0 between runs is rejected as non-maximal.
  // Built by filling the repeating two-byte pattern rather than by calling put_varint a
  // million times: push_back into a std::vector costs ~2.8 s per MiB under ASan, and the
  // buffer here is test *input*, not the thing under test. The pattern is checked against
  // put_varint once so it cannot silently stop being a real encoding.
  std::vector<uint8_t> pair_bytes;
  put_varint(pair_bytes, 1);  // gap of 1
  put_varint(pair_bytes, 0);  // run length 1
  REQUIRE(pair_bytes.size() == 2);

  std::vector<uint8_t> enc(kMaxFrame);
  for (size_t i = 0; i < enc.size(); i += 2) {
    enc[i] = pair_bytes[0];
    enc[i + 1] = pair_bytes[1];
  }
  CHECK_EQ(enc.size(), size_t{kMaxFrame});
  const size_t want_runs = kMaxFrame / 2;

  const size_t before = rss_bytes();
  auto d = NeedSet::decode(ByteSpan(enc.data(), enc.size()));
  REQUIRE(d.ok());
  const size_t after = rss_bytes();

  CHECK_EQ(d->run_count(), want_runs);
  CHECK_EQ(d->count(), want_runs);  // one index per run
  CHECK_LE(static_cast<uint64_t>(d->count()), kMaxNeedIndices);
  CHECK(d->contains(1));
  CHECK(!d->contains(2));
  CHECK(d->contains(3));
  std::printf("    note: a %u B NEED at max run density -> %zu runs, %zu indices, "
              "RSS delta %zd B\n",
              kMaxFrame, d->run_count(), d->count(),
              static_cast<ptrdiff_t>(after) - static_cast<ptrdiff_t>(before));

  // Deliberately NOT re-encoding this megabyte and NOT pushing it through a frame here.
  // Both are real properties, and both are already covered where they are cheap:
  // canonicality by needset_round_trip_random_sparse_and_dense and the two fuzzers, and a
  // kMaxFrame payload over the wire by frame_short_transfer_round_trip. Repeating them at
  // this size costs seconds of every ASan run (encode() alone is ~3.4 s for a MiB of
  // push_back) to re-prove what is already proven. What is NOT provable anywhere else is
  // the line above: a full frame yields 512 Ki runs, which is what bounds decode().
}

TEST(varint_canonicality_holds_for_every_short_buffer) {
  // The security claim in varint.h is "one number, one encoding". The tests above check
  // it against a hand-picked list of five non-canonical spellings, which proves those
  // five are caught and says nothing about the rest of the space. This proves the claim
  // outright for EVERY one- and two-byte buffer -- all 65 792 of them, which is where
  // every padding shape lives -- and then samples the long encodings, which is where the
  // overflow logic at the top of the uint64 range lives and which no short sweep reaches.
  std::vector<uint8_t> enc;
  size_t accepted = 0;
  uint8_t buf[12];

  auto probe = [&](size_t len) {
    size_t pos = 0;
    uint64_t v = 0;
    if (!get_varint(ByteSpan(buf, len), pos, v)) return;
    accepted++;
    CHECK_GT(pos, size_t{0});
    CHECK_LE(pos, len);
    enc.clear();
    put_varint(enc, v);
    // The consumed prefix IS the canonical encoding of the value it produced. Anything
    // else means two byte strings decode to one number.
    CHECK_EQ(enc.size(), pos);
    if (enc.size() == pos) CHECK(std::memcmp(enc.data(), buf, pos) == 0);
    CHECK_EQ(varint_size(v), pos);
  };

  // Lengths 1 and 2, exhaustively.
  size_t probed = 0;
  for (int a = 0; a < 256; a++) {
    buf[0] = static_cast<uint8_t>(a);
    probe(1);
    probed++;
    for (int b = 0; b < 256; b++) {
      buf[1] = static_cast<uint8_t>(b);
      probe(2);
      probed++;
    }
  }
  const size_t exhaustive = probed;

  // Lengths 3..10, sampled. Sweeping three bytes exhaustively was the first thing tried
  // and it is the wrong trade: it costs 4.2 M probes (361 s under ASan for the naive
  // form, 88 s after removing the prefixes already covered above) to explore values below
  // 2^21, while never once producing a 9- or 10-byte encoding -- which is exactly where
  // get_varint's overflow guard and its bit-63 special case live. Biasing the leading
  // bytes toward the continuation bit reaches those in a few seconds instead.
  // 50 000 rather than more: TCTX builds an ostringstream per iteration (that is the
  // price of a failure naming its own input, SPEC S15), which dominates the loop, and the
  // 3..10 byte decode paths are saturated long before this count.
  Rng rng(testing::seed() ^ 0x7a217u);
  for (int iter = 0; iter < 50000; iter++) {
    const size_t len = 3 + rng.below(8);  // 3..10
    for (size_t i = 0; i < len; i++) {
      // Mostly continuation bytes, so the decoder actually runs to its length limit;
      // a uniform byte terminates after ~1 byte and the tail is never exercised.
      const uint8_t b = rng.byte();
      buf[i] = (rng.below(4) == 0) ? static_cast<uint8_t>(b & 0x7f)
                                   : static_cast<uint8_t>(b | 0x80);
    }
    TCTX("iter=" << iter << " len=" << len);
    probe(len);
    probed++;
  }
  std::printf("    note: %zu buffers probed (%zu of them the exhaustive 1-2 byte space), "
              "%zu accepted, every one canonical\n",
              probed, exhaustive, accepted);

  // The top of the range is out of reach of a 3-byte sweep, so the two 10-byte shapes
  // that decide whether 2^64-1 has one spelling are checked directly.
  {
    std::vector<uint8_t> max_enc(9, 0xFF);
    max_enc.push_back(0x01);
    size_t pos = 0;
    uint64_t v = 0;
    REQUIRE(get_varint(ByteSpan(max_enc.data(), max_enc.size()), pos, v));
    enc.clear();
    put_varint(enc, v);
    CHECK_EQ(enc.size(), size_t{10});
    CHECK(std::memcmp(enc.data(), max_enc.data(), 10) == 0);
  }
}

TEST(frame_requests_no_payload_bytes_before_the_header_is_accepted) {
  using namespace frame_detail;
  // frame_rejects_giant_wire_len_without_allocating proves this for ONE rejection rung
  // (wire_len over the cap). Every other rung sits above the allocation too, and a reader
  // that reordered any of them would still pass that test while happily pulling a
  // megabyte off the wire for a frame it was about to throw away. So: for each rung, a
  // header carrying the largest LEGAL wire_len, and the assertion that the transport was
  // never asked for those bytes.
  struct Case {
    const char* name;
    uint8_t type;
    uint8_t flags;
    uint32_t wire_len;
    uint32_t raw_len;
    uint16_t reserved;
    uint32_t magic;
    bool recrc;  // false -> leave the CRC stale, exercising the first rung
    Err want;
  };
  const uint8_t kChunksT = static_cast<uint8_t>(FrameType::kChunks);
  const Case cases[] = {
      {"stale header crc", kChunksT, 0, kMaxFrame, kMaxFrame, 0, kFrameMagic, false,
       Err::kBadHeaderCrc},
      {"bad magic", kChunksT, 0, kMaxFrame, kMaxFrame, 0, 0xDEADBEEFu, true, Err::kBadMagic},
      {"reserved nonzero", kChunksT, 0, kMaxFrame, kMaxFrame, 1, kFrameMagic, true,
       Err::kMalformed},
      {"unknown type", 200, 0, kMaxFrame, kMaxFrame, 0, kFrameMagic, true, Err::kMalformed},
      {"unknown flag bit", kChunksT, kUndefinedFlagBit, kMaxFrame, kMaxFrame, 0, kFrameMagic,
       true, Err::kMalformed},
      {"wire_len one over cap", kChunksT, 0, kMaxFrame + 1, 0, 0, kFrameMagic, true,
       Err::kTooLarge},
      {"raw_len one over cap", kChunksT, kFlagCompressed, kMaxFrame, kMaxFrame + 1, 0,
       kFrameMagic, true, Err::kTooLarge},
      {"compressed shrinks", kChunksT, kFlagCompressed, kMaxFrame, kMaxFrame - 1, 0,
       kFrameMagic, true, Err::kMalformed},
      {"uncompressed raw_len mismatch", kChunksT, 0, kMaxFrame, 7, 0, kFrameMagic, true,
       Err::kMalformed},
  };

  for (const Case& c : cases) {
    TCTX("case=" << c.name);
    uint8_t h[32];
    put_u32_le(h + kOffMagic, c.magic);
    h[kOffType] = c.type;
    h[kOffFlags] = c.flags;
    put_u16_le(h + kOffReserved, c.reserved);
    put_u32_le(h + kOffWireLen, c.wire_len);
    put_u32_le(h + kOffRawLen, c.raw_len);
    put_u64_le(h + kOffSeq, 0);
    put_u32_le(h + kOffPayloadCrc, 0);
    put_u32_le(h + kOffHeaderCrc,
               c.recrc ? crc32c(ByteSpan(h, kHeaderCrcCoverage)) : 0xA5A5A5A5u);

    Pipe p;
    REQUIRE(write_all(*p.tx, ByteSpan(h, sizeof(h))).ok());
    p.tx->close();
    FrameReader r(*p.rx);
    auto got = r.next();
    CHECK(!got.ok());
    CHECK_EQ(got.code(), c.want);
    // The load-bearing assertion: 32 bytes read, and not one byte of the 1 MiB payload
    // the header promised. This is SPEC S7 stated as a measurement.
    CHECK_EQ(p.rx->bytes_in(), uint64_t{32});
  }
  std::printf("    note: %zu pre-allocation rejection rungs, each consumed exactly 32 B\n",
              sizeof(cases) / sizeof(cases[0]));
}

TEST(frame_writer_and_reader_enforce_the_same_header_rules) {
  using namespace frame_detail;
  // A differential test between the two halves of the codec. The hazard it exists for is
  // asymmetry: if the writer is stricter than the reader, a hostile peer has a shape we
  // never test; if the reader is stricter than the writer, an honest source emits frames
  // its own target drops, and that shows up at T8 as a mysterious hang rather than as a
  // framing bug. Neither is visible from a round-trip test, which only ever walks the
  // paths where both agree.
  // All 256 values of the flags byte, not a hand-picked pair: this is the one field where
  // a future task adds a bit (kFlagLastSlice already happened), and a sweep keeps the two
  // sides in agreement about a bit nobody remembered to add to a list here.
  const size_t payload_sizes[] = {0, 1, 64};
  const uint32_t raw_lens[] = {0, 1, 63, 64, 65, kMaxFrame, kMaxFrame + 1};

  int agree = 0, writer_only = 0, reader_only = 0;
  for (int flag_bits = 0; flag_bits < 256; flag_bits++) {
    const uint8_t flags = static_cast<uint8_t>(flag_bits);
    for (size_t sz : payload_sizes) {
      for (uint32_t rl : raw_lens) {
        TCTX("flags=" << static_cast<int>(flags) << " size=" << sz << " raw_len=" << rl);
        const std::vector<uint8_t> payload(sz, 0x5A);

        // (a) what the writer thinks of these arguments
        Pipe wp;
        FrameWriter w(*wp.tx);
        const bool writer_ok =
            w.write(FrameType::kChunks, 3, ByteSpan(payload.data(), payload.size()), flags, rl)
                .ok();

        // (b) what the reader thinks of the same fields placed on the wire verbatim --
        //     no normalization, because a peer we did not compile does not normalize.
        std::vector<uint8_t> image(32 + sz);
        put_u32_le(image.data() + kOffMagic, kFrameMagic);
        image[kOffType] = static_cast<uint8_t>(FrameType::kChunks);
        image[kOffFlags] = flags;
        put_u16_le(image.data() + kOffReserved, 0);
        put_u32_le(image.data() + kOffWireLen, static_cast<uint32_t>(sz));
        put_u32_le(image.data() + kOffRawLen, rl);
        put_u64_le(image.data() + kOffSeq, 3);
        if (sz) std::memcpy(image.data() + 32, payload.data(), sz);
        put_u32_le(image.data() + kOffPayloadCrc,
                   crc32c(ByteSpan(payload.data(), payload.size())));
        put_u32_le(image.data() + kOffHeaderCrc,
                   crc32c(ByteSpan(image.data(), kHeaderCrcCoverage)));
        auto rd = read_one(ByteSpan(image.data(), image.size()));

        // The one sanctioned asymmetry, documented in frame.h: for an uncompressed frame
        // the reader also accepts raw_len == 0 as "not applicable", which the writer
        // normalizes away. Everything else must match.
        const bool sanctioned_slack = (flags & kFlagCompressed) == 0 && rl == 0;
        if (writer_ok == rd.ok()) {
          agree++;
        } else if (writer_ok && !rd.ok()) {
          writer_only++;
          ::testing::fail(__FILE__, __LINE__,
                          "writer accepted a header its own reader rejects: " +
                              rd.error().message());
        } else {
          reader_only++;
          if (!sanctioned_slack) {
            ::testing::fail(__FILE__, __LINE__,
                            "reader accepts a header the writer refuses to produce");
          }
        }

        // And whenever the writer did produce a frame, its own reader must take it back
        // with every field intact -- the closure property that makes the codec a codec.
        if (writer_ok) {
          wp.tx->close();
          FrameReader rr(*wp.rx);
          auto back = rr.next();
          REQUIRE(back.ok());
          CHECK_EQ(back->payload.size(), sz);
          CHECK_EQ(back->flags, flags);
          if (flags & kFlagCompressed) {
            CHECK_EQ(back->raw_len, rl);
          } else {
            CHECK_EQ(back->raw_len, static_cast<uint32_t>(sz));
          }
        }
      }
    }
  }
  std::printf("    note: writer/reader agreed on %d header shapes, %d reader-only "
              "(the documented raw_len==0 slack), %d writer-only\n",
              agree, reader_only, writer_only);
  CHECK_EQ(writer_only, 0);
}

RUN_ALL()
