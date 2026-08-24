// CRC32C correctness (SPEC 3.3, S3).
//
// The safety property this suite exists for: a store written on a machine WITH
// the ARMv8 CRC instructions must verify on a machine WITHOUT them. If the
// hardware and software paths ever disagree by one bit, every chunk written on
// one machine reads back as "corrupt" on the other -- a portability bug that
// presents as data loss. So the three implementations are tested against each
// other over randomized inputs, not just against a fixed vector.
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include "wanrep/crc32c.h"
#include "wanrep/types.h"
#include "test.h"

using namespace wanrep;

namespace {
std::vector<uint8_t> random_bytes(std::mt19937_64& rng, size_t n) {
  std::vector<uint8_t> v(n);
  for (auto& b : v) b = static_cast<uint8_t>(rng() & 0xFF);
  return v;
}
}  // namespace

// The canonical CRC "check" value: the CRC of the ASCII string "123456789".
// Every CRC catalogue publishes it, and it pins down polynomial, reflection and
// the pre/post inversion all at once -- get any of those three wrong and this
// fails.
TEST(crc32c_canonical_check_value) {
  const auto s = as_bytes(std::string_view("123456789"));
  CHECK_EQ(crc32c(s), uint32_t{0xE3069283});
  CHECK_EQ(crc32c_bitwise(s), uint32_t{0xE3069283});
  CHECK_EQ(crc32c_table(s), uint32_t{0xE3069283});
}

TEST(crc32c_empty_input_is_zero) {
  const ByteSpan empty{};
  CHECK_EQ(crc32c(empty), uint32_t{0});
  CHECK_EQ(crc32c_bitwise(empty), uint32_t{0});
  CHECK_EQ(crc32c_table(empty), uint32_t{0});
}

// Differential test: the bitwise version IS the definition of the polynomial, so
// it is the oracle. Table and hardware are optimizations and must match it
// exactly, at every length -- especially the ragged tails (n % 8 != 0) where
// slicing-by-8 and the hardware's 8/4/2/1-byte ladder each have their own
// off-by-one opportunities.
TEST(crc32c_all_implementations_agree) {
  std::mt19937_64 rng(testing::seed());
  std::printf("  [info] hardware CRC32C available: %s\n",
              crc32c_has_hardware() ? "yes" : "no");
  for (size_t n = 0; n <= 300; n++) {
    TCTX("n=" << n);
    const std::vector<uint8_t> data = random_bytes(rng, n);
    const uint32_t want = crc32c_bitwise(data);
    CHECK_EQ(crc32c_table(data), want);
    CHECK_EQ(crc32c(data), want);  // whichever the dispatcher picked
#if defined(__aarch64__)
    if (crc32c_has_hardware()) CHECK_EQ(crc32c_hardware(data), want);
#endif
  }
}

// Larger, unaligned buffers: slicing-by-8 does 4-byte memcpy loads, and the
// hardware path does 8-byte ones. Feeding it a span starting at an odd offset
// checks we never assumed alignment.
TEST(crc32c_unaligned_and_large) {
  std::mt19937_64 rng(testing::seed() ^ 0x1234);
  std::vector<uint8_t> big = random_bytes(rng, 100000);
  for (size_t off : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{5}, size_t{7}}) {
    TCTX("offset=" << off);
    ByteSpan s(big.data() + off, big.size() - off);
    const uint32_t want = crc32c_bitwise(s);
    CHECK_EQ(crc32c_table(s), want);
    CHECK_EQ(crc32c(s), want);
#if defined(__aarch64__)
    if (crc32c_has_hardware()) CHECK_EQ(crc32c_hardware(s), want);
#endif
  }
}

// Chaining identity: crc(b, crc(a)) == crc(a ++ b).
// This is what lets a chunk's CRC be computed while streaming, without holding
// the whole chunk. If the pre/post inversion were mishandled, this breaks while
// the one-shot check value still passes.
TEST(crc32c_chaining_matches_concatenation) {
  std::mt19937_64 rng(testing::seed() ^ 0xC0FFEE);
  for (int trial = 0; trial < 200; trial++) {
    const size_t na = rng() % 500, nb = rng() % 500;
    const std::vector<uint8_t> a = random_bytes(rng, na);
    const std::vector<uint8_t> b = random_bytes(rng, nb);
    std::vector<uint8_t> ab = a;
    ab.insert(ab.end(), b.begin(), b.end());

    TCTX("trial=" << trial << " na=" << na << " nb=" << nb);
    CHECK_EQ(crc32c(b, crc32c(a)), crc32c(ab));
  }
}

// The property the format actually relies on (SPEC 3.3): a damaged record must
// not verify. Single-bit flips are the case CRCs are mathematically guaranteed
// to catch, and truncation is what a torn write looks like.
TEST(crc32c_detects_corruption) {
  std::mt19937_64 rng(testing::seed() ^ 0xDEAD);
  std::vector<uint8_t> data = random_bytes(rng, 8192);  // a typical chunk
  const uint32_t good = crc32c(data);

  for (int trial = 0; trial < 500; trial++) {
    std::vector<uint8_t> bad = data;
    const size_t byte = rng() % bad.size();
    bad[byte] ^= static_cast<uint8_t>(1u << (rng() % 8));
    TCTX("single-bit flip at byte=" << byte);
    CHECK_NE(crc32c(bad), good);
  }
  // Torn tail.
  for (size_t cut : {size_t{1}, size_t{100}, size_t{4096}, size_t{8191}}) {
    TCTX("truncated to " << cut);
    CHECK_NE(crc32c(ByteSpan(data.data(), cut)), good);
  }
}

RUN_ALL()
