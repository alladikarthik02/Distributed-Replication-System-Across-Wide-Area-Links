// T3: in-transit compression (SPEC 3.4, safety requirement S14).
//
// Two of these tests carry the weight, and they are not the round-trip ones:
//
//   * lz_decompressor_fuzz_on_mutated_blocks -- decompress() is the only function in
//     this project that runs on bytes a hostile peer chose, with a length and an offset
//     taken from those same bytes. The LZ77 decoder family is where this format's real
//     CVEs live. So the test does not check that valid blocks decode; it checks that
//     tens of thousands of INVALID ones produce a clean Result error and touch nothing
//     outside the output buffer. Run under ASan+UBSan, any out-of-bounds fails the task.
//
//   * lz_overlapping_matches_are_exact -- offset < match_len means the copy reads bytes
//     it is itself still producing. That is not a corner case, it is how LZ77 encodes a
//     run, and it is the single most common way to get this format subtly wrong:
//     memcpy/memmove there produces plausible-looking output that differs from the
//     input only on repetitive data -- which is exactly the data this project moves.
//     Hand-built blocks pin the semantics independently of our own encoder, so an
//     encoder/decoder pair that agrees on the WRONG answer cannot pass.
//
// A note on why the output buffers here are poisoned by hand: ASan finds a write that
// leaves the heap allocation, but a decoder that overshoots by three bytes INSIDE its
// own output buffer is invisible to it -- and that is precisely the bug an off-by-one
// in the "match length fits the remaining capacity" check would produce. The guard
// bytes catch that; ASan catches the rest. Neither alone is enough.
#include <sys/mman.h>

#include <cstdio>
#include <cstring>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "test.h"
#include "wanrep/lz.h"
#include "wanrep/types.h"

using namespace wanrep;

namespace {

// Same 4-line xorshift the other suites use: no implementation-defined behaviour across
// libstdc++ versions, and "reproducible from testing::seed()" stays auditable (SPEC S15).
struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 0x123456789abcdefull) {}
  uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
  uint32_t below(uint32_t n) { return n == 0 ? 0 : static_cast<uint32_t>(next() % n); }
  uint8_t byte() { return static_cast<uint8_t>(next() >> 24); }
};

ByteSpan span_of(const std::vector<uint8_t>& v) { return ByteSpan(v.data(), v.size()); }

// ---------------------------------------------------------------------------
// Content classes. The compressor's behaviour is a function of the DATA, so a
// round-trip test over one class proves almost nothing -- these span the range from
// "no match will ever be found" to "the whole file is one match".
// ---------------------------------------------------------------------------

std::vector<uint8_t> random_bytes(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = rng.byte();
  return v;
}

// Word soup. Stands in for the text-like part of a backup: a small vocabulary, so
// matches are frequent but short and at unpredictable distances.
std::vector<uint8_t> repetitive_text(size_t n, uint64_t seed) {
  static const char* kWords[] = {"replication ", "chunk ",  "manifest ", "generation ",
                                 "target ",      "source ", "fingerprint ", "commit ",
                                 "the ",         "a ",      "of ",       "and "};
  Rng rng(seed);
  std::vector<uint8_t> v;
  v.reserve(n + 16);
  while (v.size() < n) {
    const char* w = kWords[rng.below(12)];
    for (const char* p = w; *p; p++) v.push_back(static_cast<uint8_t>(*p));
    if (rng.below(20) == 0) v.push_back('\n');
  }
  v.resize(n);
  return v;
}

// Long runs of one byte: the case that forces offset==1 overlapping matches, i.e. the
// path where LZ77 degenerates into run-length encoding.
std::vector<uint8_t> byte_runs(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v;
  v.reserve(n + 512);
  while (v.size() < n) {
    const uint8_t b = rng.byte();
    const size_t run = 1 + rng.below(500);
    for (size_t i = 0; i < run; i++) v.push_back(b);
  }
  v.resize(n);
  return v;
}

// Fixed-size binary records: a constant tag, a counter, mostly zero padding, a little
// entropy. This is what a manifest or an index page looks like on the wire.
std::vector<uint8_t> structured_records(size_t n, uint64_t seed) {
  Rng rng(seed);
  std::vector<uint8_t> v;
  v.reserve(n + 64);
  uint32_t id = 0;
  while (v.size() < n) {
    const uint8_t rec[8] = {'C', 'H', 'N', 'K', 0, 0, 0, 0};
    for (uint8_t b : rec) v.push_back(b);
    for (int i = 0; i < 4; i++) v.push_back(static_cast<uint8_t>(id >> (8 * i)));
    id++;
    for (int i = 0; i < 44; i++) v.push_back(0);
    for (int i = 0; i < 8; i++) v.push_back(rng.byte());
  }
  v.resize(n);
  return v;
}

// A fixed-period pattern: guarantees offset < match_len for period < 4 and exercises
// the boundary where the disjoint-memcpy fast path takes over (period >= match length).
std::vector<uint8_t> periodic(size_t n, size_t period) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>('a' + (i % period));
  return v;
}

// ---------------------------------------------------------------------------
// Output buffer with poison guards on both sides (see the file header for why).
// ---------------------------------------------------------------------------
struct GuardedBuffer {
  static constexpr size_t kGuard = 32;
  static constexpr uint8_t kPoison = 0xA5;

  std::vector<uint8_t> mem;
  size_t cap;

  explicit GuardedBuffer(size_t c) : mem(c + 2 * kGuard, kPoison), cap(c) {}
  uint8_t* data() { return mem.data() + kGuard; }

  bool guards_intact() const {
    for (size_t i = 0; i < kGuard; i++) {
      if (mem[i] != kPoison) return false;
      if (mem[mem.size() - 1 - i] != kPoison) return false;
    }
    return true;
  }
};

// Returns the compressed block, or an EMPTY vector when compress() declined -- which is
// not a failure, it is SPEC S14 rule 1 firing and the caller sending the batch raw.
std::vector<uint8_t> compress_vec(const std::vector<uint8_t>& in) {
  std::vector<uint8_t> out(lz::max_compressed_size(in.size()) + 16, 0);
  const size_t k = lz::compress(span_of(in), out.data(), out.size());
  out.resize(k);
  return out;
}

void expect_round_trip(const std::vector<uint8_t>& in, const char* what) {
  TCTX(what << " n=" << in.size());
  const auto blk = compress_vec(in);
  if (blk.empty()) return;  // declined; the raw path is asserted separately

  // Rule 1 is structural, but assert it anyway: this is the property the
  // bandwidth number depends on.
  CHECK_LT(blk.size(), in.size());

  // Deliberately roomier than the payload. A tight buffer would let a decoder that
  // overruns by a few bytes hide behind the guard check firing "for the right reason";
  // with slack, the bytes past the reported length must still be untouched poison,
  // which is the stronger claim: the decoder produces EXACTLY raw_len bytes.
  constexpr size_t kSlack = 37;
  GuardedBuffer gb(in.size() + kSlack);
  auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
  if (!r.ok()) {
    ::testing::fail(__FILE__, __LINE__, "round-trip decode failed: " + r.error().message());
    return;
  }
  CHECK_EQ(*r, in.size());
  CHECK(gb.guards_intact());
  if (in.size() != 0) CHECK(std::memcmp(gb.data(), in.data(), in.size()) == 0);
  for (size_t i = in.size(); i < gb.cap; i++) CHECK_EQ(gb.data()[i], GuardedBuffer::kPoison);
}

bool detail_contains(const Error& e, const char* frag) {
  return e.detail.find(frag) != std::string::npos;
}

// Asserts a crafted block is rejected, and by WHICH check -- "it returned an error" is
// too weak a claim when a different, earlier check could be firing for a different
// reason and hiding the one under test.
void expect_rejected(const std::vector<uint8_t>& blk, size_t dst_cap, Err code,
                     const char* frag, const char* what) {
  TCTX(what);
  GuardedBuffer gb(dst_cap);
  auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
  CHECK(!r.ok());
  if (!r.ok()) {
    CHECK_EQ(static_cast<int>(r.code()), static_cast<int>(code));
    CHECK(detail_contains(r.error(), frag));
  }
  CHECK(gb.guards_intact());
}

}  // namespace

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

TEST(lz_round_trip_over_content_classes) {
  const uint64_t sd = testing::seed();
  const size_t sizes[] = {0, 1, 2, 3, 9, 10, 11, 63, 64, 1000, 4096, 8192, 100000};
  for (size_t n : sizes) {
    expect_round_trip(random_bytes(n, sd ^ n), "random");
    expect_round_trip(repetitive_text(n, sd ^ (n + 1)), "text");
    expect_round_trip(byte_runs(n, sd ^ (n + 2)), "runs");
    expect_round_trip(structured_records(n, sd ^ (n + 3)), "records");
    expect_round_trip(std::vector<uint8_t>(n, 0x00), "zeros");
    expect_round_trip(std::vector<uint8_t>(n, 0xff), "ones");
  }
}

TEST(lz_round_trip_at_format_edge_sizes) {
  const uint64_t sd = testing::seed();

  // The sizes where this format's rules change:
  //   9/10        -- the smallest input that can hold a legal match at all
  //   64Ki +/- 1  -- the match window (2-byte offset) and a plausible batch size
  //   1Mi +/- 1   -- kMaxFrame, the largest batch the wire protocol can carry (SPEC 3.2)
  //   n-5 .. n    -- the "last kLastLiterals bytes are always literals" rule
  const size_t sizes[] = {8,     9,     10,    11,    12,     13,      14,     15,
                          16,    17,    18,    19,    20,     65534,   65535,  65536,
                          65537, 65538, 65539, 65540, 131072, 1048576};
  for (size_t n : sizes) {
    // Every class, because the edge cases interact with the CONTENT: a 65537-byte run of
    // one byte exercises a match that wants to reach further back than the offset field
    // can express, which a text corpus of the same size never would.
    expect_round_trip(byte_runs(n, sd ^ n), "edge/runs");
    expect_round_trip(repetitive_text(n, sd ^ (n + 7)), "edge/text");
    expect_round_trip(std::vector<uint8_t>(n, 0x5a), "edge/const");
    expect_round_trip(periodic(n, 3), "edge/period3");
  }

  // The last-literals rule seen directly: a highly compressible body with a random,
  // incompressible tail. The tail must survive verbatim even though it can never be
  // part of a match.
  for (size_t tail = 0; tail <= 8; tail++) {
    std::vector<uint8_t> v(4096, 'q');
    const auto noise = random_bytes(tail, sd ^ (0x100 + tail));
    v.insert(v.end(), noise.begin(), noise.end());
    expect_round_trip(v, "compressible body + incompressible tail");
  }
}

// ---------------------------------------------------------------------------
// SPEC S14 rule 1: never expand
// ---------------------------------------------------------------------------

TEST(lz_never_expands_on_incompressible_input) {
  const uint64_t sd = testing::seed();
  // Random bytes have no 4-byte repeats to find (the birthday bound puts the first
  // accidental one far beyond these sizes), so the only honest answer is "send it raw".
  // If this ever returns non-zero, the "bandwidth reduction" claim in SPEC 8.1 becomes
  // a bandwidth INCREASE on every already-compressed file in the corpus.
  for (size_t n : {10u, 100u, 4096u, 65536u, 262144u, 1048576u}) {
    TCTX("n=" << n);
    const auto in = random_bytes(n, sd ^ n);
    std::vector<uint8_t> out(lz::max_compressed_size(n) + 16, 0);
    CHECK_EQ(lz::compress(span_of(in), out.data(), out.size()), size_t{0});
  }

  // The general property, on every class: whatever compress() returns, it is either 0
  // or strictly smaller than the input. There is no third option, ever.
  Rng rng(sd ^ 0xbeef);
  for (int it = 0; it < 300; it++) {
    TCTX("iter=" << it);
    const size_t n = rng.below(20000);
    std::vector<uint8_t> in;
    switch (rng.below(5)) {
      case 0: in = random_bytes(n, rng.next()); break;
      case 1: in = repetitive_text(n, rng.next()); break;
      case 2: in = byte_runs(n, rng.next()); break;
      case 3: in = structured_records(n, rng.next()); break;
      default: in = periodic(n, 1 + rng.below(9)); break;
    }
    const auto blk = compress_vec(in);
    CHECK(blk.empty() || blk.size() < in.size());
  }

  // And it holds when the caller's buffer is the binding constraint rather than the
  // input size: a tight dst_cap must produce "declined", never a truncated block.
  const auto text = repetitive_text(16384, sd ^ 0xfeed);
  const auto full = compress_vec(text);
  REQUIRE(!full.empty());
  for (size_t cap = 0; cap < full.size(); cap += 1 + full.size() / 20) {
    TCTX("cap=" << cap);
    std::vector<uint8_t> out(full.size() + 64, 0xcc);
    const size_t k = lz::compress(span_of(text), out.data(), cap);
    CHECK_EQ(k, size_t{0});
    // Nothing beyond the cap may have been touched.
    for (size_t i = cap; i < out.size(); i++) CHECK_EQ(out[i], uint8_t{0xcc});
  }
}

// ---------------------------------------------------------------------------
// SPEC S14 rule 3: overlapping matches
// ---------------------------------------------------------------------------

TEST(lz_overlapping_matches_are_exact) {
  // Periods 1..8 with lengths far beyond the period: every one of these forces the
  // encoder to emit offset < match_len, i.e. the byte-at-a-time copy path.
  for (size_t period = 1; period <= 8; period++) {
    for (size_t n : {64u, 1000u, 8192u, 70000u}) {
      TCTX("period=" << period << " n=" << n);
      const auto in = periodic(n, period);
      const auto blk = compress_vec(in);
      REQUIRE(!blk.empty());

      // A pure run should collapse to almost nothing. This is a ratio assertion, but a
      // loose one -- its job is to catch a decoder/encoder pair that "round-trips"
      // because the encoder stopped emitting long matches, which would hide a broken
      // overlapping copy behind a passing test.
      CHECK_LT(blk.size(), in.size() / 20 + 64);

      GuardedBuffer gb(in.size());
      auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
      REQUIRE(r.ok());
      CHECK_EQ(*r, in.size());
      CHECK(gb.guards_intact());
      CHECK(std::memcmp(gb.data(), in.data(), in.size()) == 0);
    }
  }

  // The same property stated independently of our encoder. These blocks are written by
  // hand from the format definition, so they pin what an overlapping match MEANS. An
  // encoder and decoder that agree with each other but not with the format would still
  // pass every round-trip test above; it cannot pass this one.
  {
    // "ab" literal, then offset 2 / length 18 -> 20 alternating bytes, then "xyz".
    const std::vector<uint8_t> blk = {0x2e, 'a', 'b', 0x02, 0x00, 0x30, 'x', 'y', 'z'};
    std::string want;
    for (int i = 0; i < 20; i++) want += (i % 2 == 0) ? 'a' : 'b';
    want += "xyz";

    GuardedBuffer gb(64);
    auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
    REQUIRE(r.ok());
    CHECK_EQ(*r, want.size());
    CHECK(gb.guards_intact());
    CHECK(std::memcmp(gb.data(), want.data(), want.size()) == 0);
  }
  {
    // Offset 1 is run-length encoding: "Q", then "the previous byte, 200 more times".
    // 200 = kMinMatch + 15 + 181, so the low nibble is 15 and one extension byte is 181.
    const std::vector<uint8_t> blk = {0x1f, 'Q', 0x01, 0x00, 181, 0x30, 'x', 'y', 'z'};
    std::string want(201, 'Q');
    want += "xyz";

    GuardedBuffer gb(300);
    auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
    REQUIRE(r.ok());
    CHECK_EQ(*r, want.size());
    CHECK(gb.guards_intact());
    CHECK(std::memcmp(gb.data(), want.data(), want.size()) == 0);
  }
}

// ---------------------------------------------------------------------------
// SPEC S14 rule 2: the decoder validates before it executes
// ---------------------------------------------------------------------------

TEST(lz_decoder_rejects_crafted_blocks) {
  // offset 0: "copy from where I am about to write". Self-referential, and in a
  // careless decoder a read of uninitialised memory.
  expect_rejected({0x40, 'a', 'a', 'a', 'a', 0x00, 0x00}, 64, Err::kMalformed,
                  "zero", "offset 0");

  // offset beyond what has been produced: 4 literals out, then a claim to copy from 100
  // bytes back. This is the classic heap underflow read in this format family.
  expect_rejected({0x40, 'a', 'a', 'a', 'a', 0x64, 0x00}, 64, Err::kMalformed,
                  "before the output start", "offset past produced output");

  // offset exactly one past the produced bytes -- the off-by-one that a `>=` vs `>`
  // slip would let through.
  expect_rejected({0x40, 'a', 'a', 'a', 'a', 0x05, 0x00}, 64, Err::kMalformed,
                  "before the output start", "offset == produced + 1");

  {
    // A huge match length: low nibble 15 plus forty 255-extension bytes ~= 10 KiB of
    // match, into a 64-byte buffer.
    std::vector<uint8_t> blk = {0x4f, 'a', 'a', 'a', 'a', 0x01, 0x00};
    for (int i = 0; i < 40; i++) blk.push_back(255);
    blk.push_back(7);
    expect_rejected(blk, 64, Err::kTooLarge, "output capacity", "huge match length");
  }
  {
    // A huge literal length in a block far too small to contain it.
    std::vector<uint8_t> blk = {0xf0};
    for (int i = 0; i < 40; i++) blk.push_back(255);
    blk.push_back(7);
    expect_rejected(blk, 1 << 20, Err::kMalformed, "block size", "huge literal length");
  }

  // Extension bytes that run off the end of the block. Note the shape: a token that
  // promises an extension must be followed by at least one byte, so the smallest block
  // that reaches this check is the token alone. (A block that carries SOME extension
  // bytes and then ends is caught one check earlier, by "a literal run cannot be longer
  // than the block encoding it" -- which is the tighter bound of the two.)
  expect_rejected({0xf0}, 1024, Err::kMalformed, "literal-length extension",
                  "literal extension with no bytes after it");
  expect_rejected({0xf0, 255, 255}, 1024, Err::kMalformed, "block size",
                  "literal extension claiming more than the block holds");
  expect_rejected({0x4f, 'a', 'a', 'a', 'a', 0x01, 0x00, 255, 255}, 1024,
                  Err::kMalformed, "match-length extension", "truncated match extension");

  // A literal run that fits the input but not the output.
  expect_rejected({0x50, 'a', 'b', 'c', 'd', 'e'}, 2, Err::kTooLarge, "output capacity",
                  "literals exceed dst_cap");

  // A literal run longer than the bytes that follow it.
  expect_rejected({0x90, 'a', 'b', 'c'}, 1024, Err::kMalformed, "remaining input",
                  "literals exceed remaining input");

  // A one-byte offset where two are required.
  expect_rejected({0x40, 'a', 'a', 'a', 'a', 0x01}, 64, Err::kMalformed,
                  "truncated match offset", "one-byte offset");

  // Structural shapes our encoder cannot produce. Rejecting these keeps the decoder's
  // reachable state space equal to the encoder's output space.
  expect_rejected({0x41, 'a', 'a', 'a', 'a'}, 64, Err::kMalformed, "final token",
                  "terminal token claims a match");
  expect_rejected({0x40, 'a', 'a', 'a', 'a', 0x01, 0x00}, 64, Err::kMalformed,
                  "literal run", "block ends after a match");
  expect_rejected({}, 64, Err::kMalformed, "literal run", "empty block");
}

TEST(lz_decoder_respects_a_tight_output_buffer) {
  const uint64_t sd = testing::seed();
  const auto in = repetitive_text(50000, sd ^ 0x77);
  const auto blk = compress_vec(in);
  REQUIRE(!blk.empty());

  // Exactly enough: must succeed and fill the buffer to the last byte.
  {
    GuardedBuffer gb(in.size());
    auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
    REQUIRE(r.ok());
    CHECK_EQ(*r, in.size());
    CHECK(gb.guards_intact());
  }
  // One byte short, and a range of tighter caps: every one must be an error, and the
  // guard bytes must be untouched -- a decoder that "clamps" instead of erroring would
  // still return a plausible size here, so the guards are what actually prove it.
  for (size_t cap = 0; cap < in.size(); cap += 1 + in.size() / 40) {
    TCTX("cap=" << cap);
    GuardedBuffer gb(cap);
    auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
    CHECK(!r.ok());
    CHECK(gb.guards_intact());
  }
  {
    TCTX("cap=size-1");
    GuardedBuffer gb(in.size() - 1);
    auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
    CHECK(!r.ok());
    CHECK(gb.guards_intact());
  }
}

// ---------------------------------------------------------------------------
// The fuzzers
// ---------------------------------------------------------------------------

TEST(lz_decompressor_fuzz_on_mutated_blocks) {
  Rng rng(testing::seed() ^ 0xf00d);

  // Mutating a VALID block is what reaches the deep decoder states: a random buffer
  // usually dies on its first token, whereas a flipped bit in a length extension gets
  // 8 KiB into a block before it lies about anything.
  std::vector<std::vector<uint8_t>> bases;
  bases.push_back(compress_vec(repetitive_text(9000, rng.next())));
  bases.push_back(compress_vec(byte_runs(9000, rng.next())));
  bases.push_back(compress_vec(structured_records(9000, rng.next())));
  bases.push_back(compress_vec(periodic(9000, 3)));
  bases.push_back(compress_vec(std::vector<uint8_t>(9000, 0x00)));
  for (const auto& b : bases) REQUIRE(!b.empty());

  constexpr int kIters = 20000;
  size_t decoded = 0, rejected = 0;
  for (int it = 0; it < kIters; it++) {
    TCTX("iter=" << it);
    std::vector<uint8_t> blk = bases[rng.below(static_cast<uint32_t>(bases.size()))];

    const int muts = 1 + static_cast<int>(rng.below(3));
    for (int m = 0; m < muts; m++) {
      switch (rng.below(6)) {
        case 0:  // flip one bit
          if (!blk.empty()) blk[rng.below(static_cast<uint32_t>(blk.size()))] ^=
              static_cast<uint8_t>(1u << rng.below(8));
          break;
        case 1:  // replace one byte outright
          if (!blk.empty()) blk[rng.below(static_cast<uint32_t>(blk.size()))] = rng.byte();
          break;
        case 2:  // truncate
          blk.resize(rng.below(static_cast<uint32_t>(blk.size() + 1)));
          break;
        case 3: {  // extend with noise
          const size_t extra = rng.below(64);
          for (size_t i = 0; i < extra; i++) blk.push_back(rng.byte());
          break;
        }
        case 4: {  // splice a piece of another block onto a prefix of this one
          const auto& other = bases[rng.below(static_cast<uint32_t>(bases.size()))];
          const size_t cut = rng.below(static_cast<uint32_t>(blk.size() + 1));
          const size_t from = rng.below(static_cast<uint32_t>(other.size()));
          blk.resize(cut);
          blk.insert(blk.end(), other.begin() + static_cast<ptrdiff_t>(from),
                     other.begin() + static_cast<ptrdiff_t>(
                                         from + rng.below(static_cast<uint32_t>(
                                                    other.size() - from + 1))));
          break;
        }
        default: {  // burst-corrupt a short run of bytes
          if (blk.empty()) break;
          const size_t at = rng.below(static_cast<uint32_t>(blk.size()));
          const size_t len = 1 + rng.below(8);
          for (size_t i = at; i < blk.size() && i < at + len; i++) blk[i] = rng.byte();
          break;
        }
      }
    }

    // Vary the output bound. Two cases in five get a buffer generous enough for the
    // whole block, so mutations deep in a block are actually REACHED rather than
    // rejected at the first capacity check; the rest make capacity the binding constraint,
    // which is the only way to exercise "does this instruction still fit".
    size_t cap;
    switch (rng.below(5)) {
      case 0: cap = 0; break;
      case 1: cap = rng.below(64); break;
      case 2: cap = rng.below(4096); break;
      default: cap = 16384; break;  // > the 9000-byte payload of every base block
    }

    GuardedBuffer gb(cap);
    auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
    if (r.ok()) {
      // A mutated block MAY still be valid -- there is no oracle for what it should
      // decode to, so what is asserted is the contract: never more than dst_cap.
      CHECK_LE(*r, gb.cap);
      decoded++;
    } else {
      rejected++;
    }
    // The claim that actually matters. ASan covers the heap; these cover the buffer.
    CHECK(gb.guards_intact());
  }
  std::printf("    note: %d mutated blocks -- %zu decoded within bounds, %zu cleanly "
              "rejected, 0 out-of-bounds\n", kIters, decoded, rejected);
}

TEST(lz_decompressor_fuzz_on_pure_random_blocks) {
  Rng rng(testing::seed() ^ 0x5a5a);
  constexpr int kIters = 20000;
  size_t decoded = 0;
  for (int it = 0; it < kIters; it++) {
    TCTX("iter=" << it);
    const size_t n = rng.below(512);
    std::vector<uint8_t> blk(n);
    for (size_t i = 0; i < n; i++) blk[i] = rng.byte();

    GuardedBuffer gb(rng.below(2048));
    auto r = lz::decompress(span_of(blk), gb.data(), gb.cap);
    if (r.ok()) {
      CHECK_LE(*r, gb.cap);
      decoded++;
    }
    CHECK(gb.guards_intact());
  }
  // Some random blocks ARE structurally valid -- short literal-only ones especially --
  // so this is a note, not an assertion. "It must always error" would be the wrong
  // requirement: the requirement is that it never crashes and never overruns.
  std::printf("    note: %d random blocks -- %zu happened to be well-formed, none out "
              "of bounds\n", kIters, decoded);
}

TEST(lz_decompressor_rejects_every_truncation) {
  // Exhaustive rather than sampled: truncation is the one corruption a dropped link
  // produces for free (SPEC 3.7), so every prefix of a real block gets tried, not a
  // random selection of them.
  const uint64_t sd = testing::seed();
  const auto in = structured_records(6000, sd ^ 0x21);
  const auto blk = compress_vec(in);
  REQUIRE(!blk.empty());

  size_t accepted = 0;
  for (size_t k = 0; k < blk.size(); k++) {
    TCTX("prefix=" << k);
    const std::vector<uint8_t> part(blk.begin(), blk.begin() + static_cast<ptrdiff_t>(k));
    GuardedBuffer gb(in.size());
    auto r = lz::decompress(span_of(part), gb.data(), gb.cap);
    if (r.ok()) {
      // A prefix that ends exactly on a sequence boundary is structurally valid; it
      // simply decodes to less data. It must never decode to MORE than the original.
      CHECK_LT(*r, in.size());
      accepted++;
    }
    CHECK(gb.guards_intact());
  }
  std::printf("    note: %zu prefixes of a %zu-byte block -- %zu structurally valid "
              "short decodes, rest cleanly rejected\n", blk.size(), blk.size(), accepted);
}

// ---------------------------------------------------------------------------
// Determinism of the encoder (see the HashTable comment in lz.h)
// ---------------------------------------------------------------------------

TEST(lz_compression_is_deterministic_despite_a_persistent_hash_table) {
  const uint64_t sd = testing::seed();
  const auto a = repetitive_text(40000, sd ^ 1);
  const auto b = structured_records(40000, sd ^ 2);

  const auto a1 = compress_vec(a);
  (void)compress_vec(b);
  (void)compress_vec(byte_runs(30000, sd ^ 3));
  const auto a2 = compress_vec(a);

  // The hash table survives between calls for throughput (zeroing 256 KiB would dwarf
  // an 8 KiB batch). This asserts the arithmetic that makes leftover entries provably
  // unusable rather than merely unlikely to matter.
  CHECK_EQ(a1.size(), a2.size());
  CHECK(a1 == a2);

  // The strongest form of the same claim: a thread that has never compressed anything
  // has a genuinely empty table. Its output must be byte-identical to ours.
  std::vector<uint8_t> fresh;
  std::thread t([&] { fresh = compress_vec(a); });
  t.join();
  CHECK_EQ(fresh.size(), a1.size());
  CHECK(fresh == a1);
}

// ---------------------------------------------------------------------------
// Measurement (SPEC 3.4: report the ratio per content class)
// ---------------------------------------------------------------------------

TEST(lz_ratio_by_content_class_note) {
  const uint64_t sd = testing::seed();
  // Small on purpose: bench/bench_lz.cpp is where the real corpus and the batch-size
  // curve live. This exists so a suite run always prints a ratio next to the safety
  // tests -- a compressor whose safety is proven and whose ratio nobody looks at is how
  // you end up shipping one that never finds a match.
  constexpr size_t kN = 512 << 10;

  struct Case { const char* name; std::vector<uint8_t> data; };
  std::vector<Case> cases;
  cases.push_back({"incompressible random", random_bytes(kN, sd ^ 11)});
  cases.push_back({"text-like", repetitive_text(kN, sd ^ 12)});
  cases.push_back({"byte runs", byte_runs(kN, sd ^ 13)});
  cases.push_back({"structured records", structured_records(kN, sd ^ 14)});
  cases.push_back({"all zeros", std::vector<uint8_t>(kN, 0)});

  for (const auto& c : cases) {
    const auto blk = compress_vec(c.data);
    if (blk.empty()) {
      std::printf("    note: %-22s -> declined (sent raw, rule 1)\n", c.name);
      continue;
    }
    std::printf("    note: %-22s -> %8zu B  (%.2fx, %.1f%% saved)\n", c.name, blk.size(),
                static_cast<double>(c.data.size()) / static_cast<double>(blk.size()),
                100.0 * (1.0 - static_cast<double>(blk.size()) /
                                   static_cast<double>(c.data.size())));
  }
}

// ===========================================================================
// Adversarial verification pass (T3 review).
//
// The tests above prove the codec agrees with ITSELF. Two of them are the stronger
// kind -- the hand-built blocks pin the format independently of our encoder -- but the
// round trips are all `compress()` checked by `decompress()`, and an encoder and a
// decoder that share a mistake pass every one of them.
//
// Everything below closes that gap, and closes the specific blind spots found by
// measuring the suite instead of trusting it: twenty-one plausible one-line defects
// were injected into lz.h one at a time and this file re-run against each. Eighteen
// die -- and exactly one of those eighteen dies ONLY in the ASan configuration, which
// is the concrete reason SPEC 6 runs all three builds instead of treating sanitizers as
// an optional extra. Three survivors are provably equivalent mutations (a guard the
// very next check subsumes, an early bound the later check repeats, an extra condition
// that changes only the ratio); they are left alone on purpose, because a test written
// to kill an equivalent mutant is a test that pins an implementation detail rather than
// a contract. The remaining FOUR were real holes, and each has a named test here:
//
//   1. A match emitted at a distance the 2-byte offset field cannot hold. The encoder
//      rejects a candidate at distance > kMaxOffset; loosen that by one and the offset
//      is written as 65536, truncates to 0x0000 on the wire, and our own decoder then
//      rejects our own block. No test above ever produced a match at exactly 65535,
//      so the check was never reached.  -> lz_encoder_reaches_the_window_edge_check
//   2. A match allowed to run into the last kLastLiterals bytes. Round trips still
//      pass (this decoder does not need the tail rule), so the structural rule that
//      the whole "end of block = input exhaustion" design rests on was unenforced.
//      -> lz_encoder_output_is_structurally_legal
//   3. compress() accepting an input above kMaxInput. That cap is not a policy knob:
//      above it the hash table's 32-bit absolute positions truncate, `cand - base`
//      stops being a position, and the encoder reads outside its own input.
//      -> lz_position_space_never_wraps / lz_compress_refuses_oversized_input
//   4. An overrun of a few bytes INSIDE the caller's buffer. GuardedBuffer catches it
//      with poison, but ASan cannot -- the allocation is cap + 64 bytes, so ASan sees
//      a legal write. The fuzzers here allocate EXACTLY dst_cap so both mechanisms are
//      live.  -> the _exactly_sized_ tests
// ===========================================================================

namespace {

// An independent decoder, written from the format description in lz.h's header comment
// rather than from lz.h's code. Deliberately different where the difference is
// observable: it grows a std::vector instead of writing into a fixed buffer, and it
// copies EVERY match one byte at a time -- so the memcpy/byte-loop split in the real
// decoder is a claim this reference can contradict rather than a shared assumption.
struct RefResult {
  bool ok = false;
  std::vector<uint8_t> out;
};

RefResult ref_decompress(const uint8_t* in, size_t n, size_t cap) {
  RefResult r;
  std::vector<uint8_t> out;
  size_t ip = 0;
  bool ended = false;
  while (ip < n) {
    const uint8_t token = in[ip++];
    uint64_t lit = token >> 4;
    if (lit == 15) {
      for (;;) {
        if (ip >= n) return r;
        const uint8_t b = in[ip++];
        lit += b;
        if (lit > n) return r;
        if (b != 255) break;
      }
    }
    if (lit > n - ip) return r;
    if (lit > cap - out.size()) return r;
    for (uint64_t i = 0; i < lit; i++) out.push_back(in[ip + static_cast<size_t>(i)]);
    ip += static_cast<size_t>(lit);
    if (ip == n) {
      if ((token & 0x0f) != 0) return r;
      ended = true;
      break;
    }
    if (n - ip < 2) return r;
    const uint32_t off = static_cast<uint32_t>(in[ip]) | (static_cast<uint32_t>(in[ip + 1]) << 8);
    ip += 2;
    if (off == 0 || off > out.size()) return r;
    uint64_t mlen = token & 0x0f;
    if (mlen == 15) {
      for (;;) {
        if (ip >= n) return r;
        const uint8_t b = in[ip++];
        mlen += b;
        if (mlen > cap) return r;
        if (b != 255) break;
      }
    }
    mlen += lz::kMinMatch;
    if (mlen > cap - out.size()) return r;
    for (uint64_t i = 0; i < mlen; i++) {
      const uint8_t v = out[out.size() - off];  // by value: push_back may reallocate
      out.push_back(v);
    }
  }
  if (!ended) return r;
  r.ok = true;
  r.out = std::move(out);
  return r;
}

// What a block SAYS about itself, recovered by parsing it. Used to assert the encoder's
// obligations (SPEC 3.4) rather than merely that its output happens to decode.
struct BlockShape {
  bool legal = true;
  const char* why = "";
  size_t produced = 0;      // total output bytes the block describes
  uint32_t max_offset = 0;  // the furthest back any match reached
  size_t final_literals = 0;
  size_t matches = 0;
};

BlockShape inspect_block(const std::vector<uint8_t>& b) {
  BlockShape s;
  size_t ip = 0;
  bool ended = false;
  auto bad = [&s](const char* w) { s.legal = false; s.why = w; return s; };
  while (ip < b.size()) {
    const uint8_t token = b[ip++];
    uint64_t lit = token >> 4;
    if (lit == 15) {
      for (;;) {
        if (ip >= b.size()) return bad("literal extension runs off the block");
        const uint8_t x = b[ip++];
        lit += x;
        if (x != 255) break;
      }
    }
    if (lit > b.size() - ip) return bad("literal run runs off the block");
    ip += static_cast<size_t>(lit);
    s.produced += static_cast<size_t>(lit);
    if (ip == b.size()) {
      if ((token & 0x0f) != 0) return bad("final token declares a match");
      ended = true;
      s.final_literals = static_cast<size_t>(lit);
      break;
    }
    if (b.size() - ip < 2) return bad("truncated offset");
    const uint32_t off = static_cast<uint32_t>(b[ip]) | (static_cast<uint32_t>(b[ip + 1]) << 8);
    ip += 2;
    if (off == 0) return bad("offset 0 -- the 2-byte field wrapped");
    if (off > s.produced) return bad("offset reaches before the output start");
    if (off > lz::kMaxOffset) return bad("offset past the match window");
    if (off > s.max_offset) s.max_offset = off;
    uint64_t mlen = token & 0x0f;
    if (mlen == 15) {
      for (;;) {
        if (ip >= b.size()) return bad("match extension runs off the block");
        const uint8_t x = b[ip++];
        mlen += x;
        if (x != 255) break;
      }
    }
    mlen += lz::kMinMatch;
    s.produced += static_cast<size_t>(mlen);
    s.matches++;
  }
  if (!ended) return bad("block does not end with a literal run");
  return s;
}

// An output buffer of EXACTLY dst_cap bytes. GuardedBuffer above deliberately
// over-allocates so its poison can see an overrun that stays inside the allocation;
// this is the complement, and the two together are what makes "never writes outside
// dst[0, dst_cap)" a claim with no gap in the middle: ASan owns the bytes past the
// allocation, the poison owns the bytes between the reported length and the cap.
struct ExactBuffer {
  std::unique_ptr<uint8_t[]> mem;
  size_t cap;
  explicit ExactBuffer(size_t c) : mem(new uint8_t[c ? c : 1]), cap(c) {}
  uint8_t* data() { return mem.get(); }
};

// Runs one block through both decoders and asserts they agree on everything observable.
// Returns false on the first disagreement so a fuzz loop can stop instead of printing
// ten thousand identical failures.
bool decoders_agree(const uint8_t* blk, size_t n, size_t cap, size_t* accepted) {
  GuardedBuffer gb(cap);
  auto mine = lz::decompress(ByteSpan(blk, n), gb.data(), gb.cap);
  const RefResult theirs = ref_decompress(blk, n, cap);
  if (!gb.guards_intact()) return false;
  if (mine.ok() != theirs.ok) return false;
  if (mine.ok()) {
    if (*mine != theirs.out.size()) return false;
    if (!theirs.out.empty() && std::memcmp(gb.data(), theirs.out.data(), theirs.out.size()) != 0)
      return false;
    if (accepted != nullptr) (*accepted)++;
  }
  // Again with an exactly-sized buffer, so ASan is the one holding the far edge.
  ExactBuffer eb(cap);
  auto again = lz::decompress(ByteSpan(blk, n), eb.data(), eb.cap);
  if (again.ok() != mine.ok()) return false;
  if (again.ok() && *again != *mine) return false;
  return true;
}

// A failing fuzz case is only reproducible if the failure prints the block, so this is
// part of the test, not a debugging aid left behind.
std::string hex_of(const uint8_t* p, size_t n) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string s;
  s.reserve(n * 3);
  for (size_t i = 0; i < n; i++) {
    s += kHex[p[i] >> 4];
    s += kHex[p[i] & 0x0f];
    s += ' ';
  }
  return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// The encoder's obligations, checked structurally rather than by round trip
// ---------------------------------------------------------------------------

TEST(lz_encoder_output_is_structurally_legal) {
  const uint64_t sd = testing::seed();
  Rng rng(sd ^ 0x5171);

  // Every rule SPEC 3.4 places on the ENCODER, asserted by parsing what it emitted:
  // an offset it can actually write into two bytes, an offset inside what the decoder
  // will have produced, a match no shorter than kMinMatch, and -- the one no round trip
  // can see -- a final literal run of at least kLastLiterals bytes, which is the entire
  // reason input exhaustion is a safe end-of-block signal.
  size_t blocks = 0, matches = 0;
  auto check_one = [&](const std::vector<uint8_t>& in, const char* what) {
    TCTX(what << " n=" << in.size());
    const auto blk = compress_vec(in);
    if (blk.empty()) return;
    const BlockShape s = inspect_block(blk);
    if (!s.legal) {
      ::testing::fail(__FILE__, __LINE__, std::string("illegal block: ") + s.why);
      return;
    }
    CHECK_EQ(s.produced, in.size());
    CHECK_GE(s.final_literals, lz::kLastLiterals);
    blocks++;
    matches += s.matches;

    // And decoded by something that is not lz::decompress, so an encoder and a decoder
    // that share a misreading of the format cannot both be wrong and both pass.
    const RefResult r = ref_decompress(blk.data(), blk.size(), in.size());
    REQUIRE(r.ok);
    CHECK(r.out == in);
  };

  for (size_t n = 0; n <= 400; n++) {
    check_one(random_bytes(n, sd ^ n), "random");
    check_one(repetitive_text(n, sd ^ (n + 1)), "text");
    check_one(byte_runs(n, sd ^ (n + 2)), "runs");
    check_one(periodic(n, 1), "period1");
    check_one(periodic(n, 3), "period3");
    check_one(std::vector<uint8_t>(n, 0x00), "zeros");
  }
  for (int it = 0; it < 90; it++) {
    const size_t n = rng.below(120000);
    switch (rng.below(5)) {
      case 0: check_one(random_bytes(n, rng.next()), "big/random"); break;
      case 1: check_one(repetitive_text(n, rng.next()), "big/text"); break;
      case 2: check_one(byte_runs(n, rng.next()), "big/runs"); break;
      case 3: check_one(structured_records(n, rng.next()), "big/records"); break;
      default: check_one(periodic(n, 1 + rng.below(400)), "big/periodic"); break;
    }
  }
  std::printf("    note: %zu encoder blocks parsed, %zu matches, all structurally legal\n",
              blocks, matches);
}

// ---------------------------------------------------------------------------
// The match window edge -- the one encoder check no round-trip test reaches
// ---------------------------------------------------------------------------

TEST(lz_encoder_reaches_the_window_edge_check) {
  // WHY THIS TEST IS BUILT AND NOT SAMPLED: `cur - cand > kMaxOffset` is the check that
  // keeps the encoder inside the 2-byte offset field. Loosen it by one and the encoder
  // emits offset 65536, which truncates to 0x0000 on the wire -- a block our own
  // decoder rejects as "match offset is zero". None of the round-trip tests above ever
  // produced a match at exactly 65535, so that check was live code no test executed.
  //
  // The construction: marker | 'z' * (D-8) | marker | random tail. Position 0 is seeded
  // into the hash table before the scan starts, the run of 'z' collapses into one match
  // that ends exactly where the second marker begins, so the scan resumes at exactly
  // position D and probes the same 4-byte sequence it stored at position 0. Distance D
  // is therefore chosen, not hoped for.
  //
  // The marker has to be one whose hash slot nothing else in the input overwrites,
  // which depends on lz.h's hash function -- so it is SEARCHED for rather than
  // hard-coded, and the search asserts it succeeded. If a future change to the matcher
  // makes this construction stop reaching the check, the REQUIRE below fails loudly
  // rather than the test quietly becoming a no-op.
  auto build = [](const uint8_t m[8], size_t distance, uint64_t tail_seed) {
    std::vector<uint8_t> v;
    v.insert(v.end(), m, m + 8);
    v.insert(v.end(), distance - 8, 'z');
    v.insert(v.end(), m, m + 8);
    const auto tail = random_bytes(64, tail_seed);
    v.insert(v.end(), tail.begin(), tail.end());
    return v;
  };

  Rng rng(testing::seed() ^ 0xfff1);
  uint8_t marker[8] = {0};
  bool found = false;
  for (int attempt = 0; attempt < 512 && !found; attempt++) {
    for (auto& b : marker) b = rng.byte();
    if (marker[0] == 'z') continue;
    const auto in = build(marker, lz::kMaxOffset, 0x9e3779b9ull);
    const auto blk = compress_vec(in);
    if (blk.empty()) continue;
    const BlockShape s = inspect_block(blk);
    found = s.legal && s.max_offset == lz::kMaxOffset;
  }
  REQUIRE(found);  // the construction no longer reaches the check -- fix the construction

  // At exactly kMaxOffset the match is legal and must be taken, at exactly one past it
  // the candidate must be refused. Both blocks must be structurally legal and both must
  // round-trip; the difference is only in whether that one match appears.
  struct Case { size_t distance; bool expect_edge_match; };
  const Case cases[] = {{lz::kMaxOffset - 1, false},
                        {lz::kMaxOffset, true},
                        {lz::kMaxOffset + 1, false},
                        {lz::kMaxOffset + 2, false}};
  for (const auto& c : cases) {
    TCTX("distance=" << c.distance);
    const auto in = build(marker, c.distance, 0x9e3779b9ull);
    const auto blk = compress_vec(in);
    REQUIRE(!blk.empty());
    const BlockShape s = inspect_block(blk);
    if (!s.legal) {
      ::testing::fail(__FILE__, __LINE__, std::string("illegal block: ") + s.why);
      continue;
    }
    CHECK_LE(s.max_offset, lz::kMaxOffset);
    if (c.expect_edge_match) {
      CHECK_EQ(s.max_offset, lz::kMaxOffset);
    } else {
      CHECK_LT(s.max_offset, lz::kMaxOffset);
    }
    const RefResult r = ref_decompress(blk.data(), blk.size(), in.size());
    REQUIRE(r.ok);
    CHECK(r.out == in);
  }
  std::printf("    note: window edge exercised at distances %u-1 .. %u+2\n",
              lz::kMaxOffset, lz::kMaxOffset);
}

// ---------------------------------------------------------------------------
// The position space the persistent hash table lives in
// ---------------------------------------------------------------------------

TEST(lz_position_space_never_wraps) {
  // The determinism argument in lz.h is arithmetic: entries hold an ABSOLUTE position,
  // and each call advances `base` far enough that every leftover entry fails the
  // distance check. That argument has two failure modes neither reachable by compressing
  // normal-sized buffers -- the counter running out after ~4 GiB on one thread, and an
  // input large enough for `base + n` to wrap a uint32. Both are asserted directly here,
  // on a local table, because reaching either through compress() would mean moving
  // gigabytes per test run.
  {
    lz::detail::HashTable t;
    uint32_t prev_base = 0, prev_n = 0;
    bool have_prev = false;
    size_t restarts = 0;
    Rng rng(testing::seed() ^ 0x0ffff);
    for (int i = 0; i < 400; i++) {
      TCTX("reserve iter=" << i);
      // A mix of realistic batches and the largest input compress() will ever accept,
      // so the ~4 GiB restart is actually reached inside this loop.
      const size_t n = (i % 8 == 0) ? lz::kMaxInput : (1 + rng.below(1u << 20));
      const uint32_t b = t.reserve(n);

      // No position this call will use may wrap the 32-bit counter.
      CHECK_LE(uint64_t{b} + n, 0xFFFFFFFFull);

      if (have_prev) {
        const uint64_t last_of_prev = uint64_t{prev_base} + prev_n - 1;
        if (b >= prev_base) {
          // Same epoch: this call's first position must be further than the whole match
          // window beyond the previous call's last position, which is what makes every
          // stale entry unusable without a sentinel or a memset.
          CHECK_GT(uint64_t{b} - last_of_prev, uint64_t{lz::kMaxOffset});
        } else {
          // The counter restarted; the table was cleared, so staleness is moot.
          restarts++;
          CHECK_EQ(b, lz::kMaxOffset + 1);
        }
      }
      prev_base = b;
      prev_n = static_cast<uint32_t>(n);
      have_prev = true;
    }
    CHECK_GT(restarts, size_t{0});  // the restart path must actually have been taken
    std::printf("    note: 400 reserves, %zu counter restarts, no position wrapped\n",
                restarts);
  }

  // And the observable consequence: a thread whose counter is about to restart still
  // compresses to exactly the same bytes as a thread that has never compressed anything.
  {
    const auto in = repetitive_text(40000, testing::seed() ^ 0x3131);
    const auto want = compress_vec(in);
    REQUIRE(!want.empty());
    const uint32_t bases[] = {lz::kMaxOffset + 1, 0x7FFFFFFFu, 0xFFFF0000u, 0xFFFFFFFFu};
    for (uint32_t b : bases) {
      TCTX("base=" << b);
      lz::detail::thread_table().base = b;
      CHECK(compress_vec(in) == want);
    }
    lz::detail::thread_table().base = lz::kMaxOffset + 1;
  }
}

TEST(lz_compress_refuses_oversized_input) {
  // kMaxInput is not a policy knob, it is a memory-safety bound: above it the hash
  // table's 32-bit absolute positions truncate, `cand - base` stops naming a position
  // inside this call, and the encoder reads outside its own input. The contract is that
  // compress() declines BEFORE it touches a single byte -- so the span handed over here
  // points at a PROT_NONE mapping. Nothing reads it, and the mapping is real, so this is
  // not a fabricated pointer; if the cap were ever removed the very first read faults
  // and this test dies loudly rather than passing quietly.
  const size_t n = lz::kMaxInput + 1;
  void* p = ::mmap(nullptr, n, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  REQUIRE(p != MAP_FAILED);
  std::vector<uint8_t> out(64, 0xcc);
  const size_t k = lz::compress(ByteSpan(static_cast<const uint8_t*>(p), n), out.data(), out.size());
  CHECK_EQ(k, size_t{0});
  for (uint8_t b : out) CHECK_EQ(b, uint8_t{0xcc});
  ::munmap(p, n);
}

// ---------------------------------------------------------------------------
// Decoder: agreement with an independent implementation, on hostile input
// ---------------------------------------------------------------------------

TEST(lz_decoder_agrees_with_an_independent_decoder) {
  // Exhaustive over every short block, because short blocks are where the decoder's
  // state machine has the least input to disagree about and the most edges: the first
  // token, the end-of-block test, the two-byte offset that may not fit. Every one is
  // run against the reference AND against an exactly-sized output buffer.
  static const uint8_t kAlphabet[] = {0x00, 0x01, 0x02, 0x04, 0x0f, 0x10, 0x1f,
                                      0x40, 0x4f, 0x50, 0x90, 0xf0, 0xff};
  // Every capacity for the short tiers; the 4-byte tier is 13x bigger, so it keeps only
  // the three that bracket a decision (nothing fits / a match's minimum fits / room to
  // spare). Dropping it entirely would lose the only tier long enough to hold a token,
  // an offset and a second token at once.
  static const size_t kCapsShort[] = {0, 1, 4, 5, 20};
  static const size_t kCapsLong[] = {0, 5, 20};
  constexpr size_t kAlpha = sizeof(kAlphabet);

  size_t cases = 0, accepted = 0;
  std::vector<uint8_t> blk;
  for (size_t len = 0; len <= 4; len++) {
    const size_t* caps = (len <= 3) ? kCapsShort : kCapsLong;
    const size_t ncaps = (len <= 3) ? std::size(kCapsShort) : std::size(kCapsLong);
    std::vector<size_t> idx(len, 0);
    for (;;) {
      blk.assign(len, 0);
      for (size_t i = 0; i < len; i++) blk[i] = kAlphabet[idx[i]];
      for (size_t ci = 0; ci < ncaps; ci++) {
        const size_t cap = caps[ci];
        if (!decoders_agree(blk.data(), blk.size(), cap, &accepted)) {
          ::testing::fail(__FILE__, __LINE__,
                          "decoders disagree, cap=" + std::to_string(cap) + " block=" +
                              hex_of(blk.data(), blk.size()));
          return;
        }
        cases++;
      }
      size_t d = 0;
      while (d < len && ++idx[d] == kAlpha) { idx[d] = 0; d++; }
      if (d == len) break;
    }
  }
  // Every block our encoder actually emits, decoded both ways at the exact capacity the
  // frame header would have declared (SPEC 3.2's raw_len).
  const uint64_t sd = testing::seed();
  for (size_t n : {1000u, 8192u, 65536u, 200000u}) {
    const std::vector<uint8_t> corpus[] = {repetitive_text(n, sd ^ n), byte_runs(n, sd ^ (n + 1)),
                                           structured_records(n, sd ^ (n + 2)), periodic(n, 5)};
    for (const auto& in : corpus) {
      const auto b = compress_vec(in);
      if (b.empty()) continue;
      if (!decoders_agree(b.data(), b.size(), in.size(), &accepted)) {
        ::testing::fail(__FILE__, __LINE__, "decoders disagree on a real block");
        return;
      }
      cases++;
    }
  }
  std::printf("    note: %zu blocks decoded twice by two implementations, %zu accepted, "
              "no disagreement\n", cases, accepted);
}

TEST(lz_decoder_fuzz_grammar_directed) {
  // Bit-flipping a valid block is good at reaching deep states but bad at reaching
  // BOUNDARY states: a random flip almost never lands a length exactly on the remaining
  // capacity. This generator builds syntactically shaped sequences whose every field is
  // drawn from the set {0, 1, exactly the limit, one past the limit, the extension
  // boundary}, which is where an off-by-one lives, and only then corrupts them.
  Rng rng(testing::seed() ^ 0x9111);
  constexpr int kIters = 20000;
  size_t accepted = 0;

  auto put_extension = [](std::vector<uint8_t>& v, size_t value_above_15) {
    size_t rest = value_above_15 - 15;
    for (; rest >= 255; rest -= 255) v.push_back(255);
    v.push_back(static_cast<uint8_t>(rest));
  };

  for (int it = 0; it < kIters; it++) {
    TCTX("iter=" << it);
    std::vector<uint8_t> blk;
    const size_t cap = (rng.below(4) == 0) ? rng.below(32) : rng.below(4000);
    size_t claimed = 0;  // output bytes the block claims so far, so offsets can straddle it
    const int seqs = 1 + static_cast<int>(rng.below(6));
    for (int s = 0; s < seqs; s++) {
      size_t lit;
      switch (rng.below(6)) {
        case 0: lit = 0; break;
        case 1: lit = rng.below(16); break;
        case 2: lit = 14 + rng.below(4); break;                      // the 15-nibble edge
        case 3: lit = 268 + rng.below(6); break;                     // the 255-extension edge
        case 4: lit = (cap > claimed) ? cap - claimed : 0; break;    // exactly the capacity
        default: lit = rng.below(200); break;
      }
      const bool last = (s == seqs - 1) && (rng.below(4) != 0);
      uint32_t off = 0;
      size_t mlen = 0;
      if (!last) {
        switch (rng.below(6)) {
          case 0: off = 0; break;
          case 1: off = 1; break;
          case 2: off = static_cast<uint32_t>(claimed + lit); break;      // exactly produced
          case 3: off = static_cast<uint32_t>(claimed + lit + 1); break;  // one past produced
          case 4: off = lz::kMaxOffset; break;
          default: off = rng.below(300); break;
        }
        switch (rng.below(6)) {
          case 0: mlen = lz::kMinMatch; break;
          case 1: mlen = lz::kMinMatch + rng.below(15); break;
          case 2: mlen = 18 + rng.below(4); break;
          case 3: mlen = 272 + rng.below(6); break;
          case 4: mlen = (cap > claimed + lit) ? cap - claimed - lit : lz::kMinMatch; break;
          default: mlen = lz::kMinMatch + rng.below(400); break;
        }
        if (mlen < lz::kMinMatch) mlen = lz::kMinMatch;
      }
      const size_t mtok = last ? 0 : (mlen - lz::kMinMatch);
      uint8_t token = static_cast<uint8_t>((lit >= 15 ? 15u : lit) << 4);
      if (!last) token |= static_cast<uint8_t>(mtok >= 15 ? 15u : mtok);
      blk.push_back(token);
      if (lit >= 15) put_extension(blk, lit);
      for (size_t i = 0; i < lit; i++) blk.push_back(rng.byte());
      claimed += lit;
      if (last) break;
      blk.push_back(static_cast<uint8_t>(off & 0xff));
      blk.push_back(static_cast<uint8_t>(off >> 8));
      if (mtok >= 15) put_extension(blk, mtok);
      claimed += mlen;
    }
    // Then leave the grammar, so "syntactically shaped" does not become "always valid".
    if (rng.below(3) == 0 && !blk.empty())
      blk.resize(rng.below(static_cast<uint32_t>(blk.size() + 1)));
    if (rng.below(4) == 0 && !blk.empty())
      blk[rng.below(static_cast<uint32_t>(blk.size()))] = rng.byte();

    if (!decoders_agree(blk.data(), blk.size(), cap, &accepted)) {
      ::testing::fail(__FILE__, __LINE__,
                      "decoders disagree, cap=" + std::to_string(cap) + " block=" +
                          hex_of(blk.data(), blk.size()));
      return;
    }
  }
  std::printf("    note: %d grammar-directed blocks, %zu accepted, two decoders agreed "
              "on every one\n", kIters, accepted);
}

TEST(lz_decoder_fuzz_with_an_exactly_sized_output_buffer) {
  // The same mutation fuzz as above, but the destination is a heap allocation of
  // EXACTLY dst_cap bytes. GuardedBuffer's poison can see a small overrun that stays
  // inside a padded allocation; ASan can only see one that leaves the allocation. Run
  // the corpus through both shapes or neither mechanism is complete (SPEC S14).
  Rng rng(testing::seed() ^ 0xe0e0);
  std::vector<std::vector<uint8_t>> bases;
  bases.push_back(compress_vec(repetitive_text(9000, rng.next())));
  bases.push_back(compress_vec(byte_runs(9000, rng.next())));
  bases.push_back(compress_vec(periodic(9000, 3)));
  bases.push_back(compress_vec(std::vector<uint8_t>(9000, 0x00)));
  for (const auto& b : bases) REQUIRE(!b.empty());

  constexpr int kIters = 20000;
  size_t decoded = 0;
  for (int it = 0; it < kIters; it++) {
    TCTX("iter=" << it);
    std::vector<uint8_t> blk = bases[rng.below(static_cast<uint32_t>(bases.size()))];
    const int muts = 1 + static_cast<int>(rng.below(4));
    for (int m = 0; m < muts; m++) {
      switch (rng.below(5)) {
        case 0:
          if (!blk.empty())
            blk[rng.below(static_cast<uint32_t>(blk.size()))] ^=
                static_cast<uint8_t>(1u << rng.below(8));
          break;
        case 1:
          if (!blk.empty()) blk[rng.below(static_cast<uint32_t>(blk.size()))] = rng.byte();
          break;
        case 2: blk.resize(rng.below(static_cast<uint32_t>(blk.size() + 1))); break;
        case 3: {
          const size_t extra = rng.below(48);
          for (size_t i = 0; i < extra; i++) blk.push_back(rng.byte());
          break;
        }
        default: {
          if (blk.empty()) break;
          const size_t at = rng.below(static_cast<uint32_t>(blk.size()));
          for (size_t i = at; i < blk.size() && i < at + 8; i++) blk[i] = rng.byte();
          break;
        }
      }
    }
    size_t cap;
    switch (rng.below(5)) {
      case 0: cap = 0; break;
      case 1: cap = rng.below(64); break;
      case 2: cap = rng.below(4096); break;
      default: cap = 16384; break;
    }
    ExactBuffer eb(cap);
    auto r = lz::decompress(ByteSpan(blk.data(), blk.size()), eb.data(), eb.cap);
    if (r.ok()) {
      CHECK_LE(*r, eb.cap);
      decoded++;
    }
  }
  std::printf("    note: %d mutated blocks into exactly-sized buffers -- %zu decoded, "
              "ASan saw no overrun\n", kIters, decoded);
}

TEST(lz_compress_never_writes_past_dst_cap) {
  // The mirror of the decoder tests: the ENCODER also takes a caller-supplied bound, and
  // a truncated block on the wire would be a corrupt transfer rather than a caught error
  // (SPEC S14 rule 1 is what turns "does not fit" into "send it raw"). dst is allocated
  // at exactly dst_cap so ASan owns the far edge here too.
  const uint64_t sd = testing::seed();
  Rng rng(sd ^ 0xcafe);
  for (int it = 0; it < 800; it++) {
    TCTX("iter=" << it);
    const size_t n = rng.below(9000);
    std::vector<uint8_t> in;
    switch (rng.below(5)) {
      case 0: in = random_bytes(n, rng.next()); break;
      case 1: in = repetitive_text(n, rng.next()); break;
      case 2: in = byte_runs(n, rng.next()); break;
      case 3: in = periodic(n, 1 + rng.below(20)); break;
      default: in = structured_records(n, rng.next()); break;
    }
    const size_t cap = rng.below(static_cast<uint32_t>(n + 64));
    ExactBuffer eb(cap);
    const size_t k = lz::compress(span_of(in), eb.data(), eb.cap);
    CHECK_LE(k, cap);
    CHECK(k == 0 || k < in.size());
  }

  // And the property the existing cap sweep states only in one direction: once the
  // caller's buffer is big enough, the answer stops depending on it. The parse is a
  // function of the input alone, so every roomier cap must give byte-identical output --
  // otherwise "compress() is deterministic" would hold only for one buffer size.
  const auto text = repetitive_text(20000, sd ^ 0x2020);
  const auto full = compress_vec(text);
  REQUIRE(!full.empty());
  for (size_t cap = full.size(); cap <= full.size() + 32; cap++) {
    TCTX("cap=" << cap);
    ExactBuffer eb(cap);
    const size_t k = lz::compress(span_of(text), eb.data(), eb.cap);
    CHECK_EQ(k, full.size());
    if (k == full.size()) CHECK(std::memcmp(eb.data(), full.data(), k) == 0);
  }
}

TEST(lz_compression_is_identical_across_threads) {
  // The hash table is thread_local (SPEC 3.6 runs M compressor threads). The existing
  // determinism test uses one fresh thread; this one runs several concurrently, each
  // repeatedly, so a table that was accidentally shared shows up as a ratio difference
  // between threads rather than as a race no assertion would notice. Also the case TSan
  // needs to see something to report.
  const auto in = repetitive_text(50000, testing::seed() ^ 0x7373);
  const auto want = compress_vec(in);
  REQUIRE(!want.empty());

  constexpr int kThreads = 8;
  std::vector<std::vector<uint8_t>> got(kThreads);
  // uint8_t, NOT std::vector<bool>: the latter packs eight results into one word, so
  // eight threads each writing "their own" element are in fact writing one shared word.
  // TSan calls that exactly what it is, and it is worth naming here because it is the
  // same class of mistake as sharing a cache line between a ring's head and tail
  // (SPEC 2.5) -- a variable that looks per-thread and is not.
  std::vector<uint8_t> same(kThreads, 0);
  std::vector<std::thread> ts;
  for (int i = 0; i < kThreads; i++) {
    ts.emplace_back([&, i] {
      bool ok = true;
      for (int r = 0; r < 6; r++) {
        got[i] = compress_vec(in);
        // Interleave other work so this thread's table is dirty in a different way each
        // round -- which is exactly what the position-base arithmetic has to absorb.
        (void)compress_vec(byte_runs(3000 + 700 * static_cast<size_t>(r), 0x11 + r));
        if (got[i] != want) ok = false;
      }
      same[i] = ok ? 1 : 0;
    });
  }
  for (auto& t : ts) t.join();
  for (int i = 0; i < kThreads; i++) {
    TCTX("thread=" << i);
    CHECK(same[i] != 0);
  }
}


RUN_ALL()
