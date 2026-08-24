// SHA-256 correctness (SPEC R1.2).
//
// The primary oracle is the set of published NIST FIPS 180-4 / CAVP vectors.
// Those are not arbitrary strings -- their lengths were chosen to exercise the
// padding boundaries, which is where hand-written SHA implementations break:
//   ""      0 bytes    -> padding is the entire (only) block
//   "abc"   3 bytes    -> ordinary one-block case
//   56 bytes           -> the KILLER case: 56 + 1 marker + 8 length = 65 > 64,
//                         so padding must spill into a SECOND block
//   112 bytes          -> multi-block message + spilling padding
//   1,000,000 'a'      -> 15625 blocks; catches a broken length counter
#include <cstdio>
#include <random>
#include <utility>
#include <string>
#include <vector>

#include "wanrep/sha256.h"
#include "wanrep/types.h"
#include "test.h"

using namespace wanrep;

namespace {

struct Vector {
  const char* message;
  const char* expected_hex;
};

// FIPS 180-4 Appendix B / NIST example vectors.
const Vector kVectors[] = {
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopq"
     "rlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
};

std::vector<uint8_t> random_bytes(std::mt19937_64& rng, size_t n) {
  std::vector<uint8_t> v(n);
  for (auto& b : v) b = static_cast<uint8_t>(rng() & 0xFF);
  return v;
}

// Every correctness test runs against every backend this CPU can actually
// execute. The scalar path is not "the slow one we don't care about" -- it is
// the path a machine without the SHA-2 extension runs, and a store must be
// readable on both.
std::vector<std::pair<const char*, HashBackend>> backends() {
  std::vector<std::pair<const char*, HashBackend>> v{{"scalar", HashBackend::kScalar}};
  if (sha256_has_hardware()) v.push_back({"hardware", HashBackend::kHardware});
  return v;
}

}  // namespace

TEST(sha256_nist_vectors) {
  std::printf("  [info] hardware SHA-256 available: %s\n",
              sha256_has_hardware() ? "yes" : "no");
  for (const auto& [label, backend] : backends()) {
    for (const auto& v : kVectors) {
      TCTX(label << " len=" << std::string(v.message).size());
      const Digest32 got = sha256(as_bytes(std::string_view(v.message)), backend);
      CHECK_EQ(to_hex(got), std::string(v.expected_hex));
    }
  }
}

// The million-'a' vector: 15,625 compression rounds. A truncated or wrapped
// length counter produces the right answer for short inputs and the wrong one
// here, which is exactly why NIST includes it.
TEST(sha256_nist_million_a) {
  std::vector<uint8_t> msg(1000000, 'a');
  for (const auto& [label, backend] : backends()) {
    TCTX(label);
    CHECK_EQ(to_hex(sha256(msg, backend)),
             std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
  }
}

// The safety property behind having two backends at all: a fingerprint computed
// on a CPU with the SHA-2 extension must equal the one computed without it. If
// they ever diverged, a store written on one machine would dedup incorrectly and
// fail verification on another -- silent, portable data corruption. Lengths sweep
// every block-boundary and padding-spill case, not just round numbers.
TEST(sha256_scalar_and_hardware_agree) {
  if (!sha256_has_hardware()) {
    std::printf("  [skip] no hardware SHA-2 on this CPU\n");
    return;
  }
  std::mt19937_64 rng(testing::seed() ^ 0x5EED);
  for (size_t n = 0; n <= 600; n++) {
    TCTX("n=" << n);
    const std::vector<uint8_t> data = random_bytes(rng, n);
    CHECK_EQ(to_hex(sha256(data, HashBackend::kScalar)),
             to_hex(sha256(data, HashBackend::kHardware)));
  }
  // A multi-block buffer, plus a streamed version, so the batched multi-block
  // call path in update() is covered too.
  const std::vector<uint8_t> big = random_bytes(rng, 1 << 20);
  CHECK_EQ(to_hex(sha256(big, HashBackend::kScalar)),
           to_hex(sha256(big, HashBackend::kHardware)));

  Sha256 hw(HashBackend::kHardware);
  size_t pos = 0;
  while (pos < big.size()) {
    const size_t take = std::min<size_t>(big.size() - pos, 1 + rng() % 5000);
    hw.update(big.data() + pos, take);
    pos += take;
  }
  CHECK_EQ(to_hex(hw.finish()), to_hex(sha256(big, HashBackend::kScalar)));
}

// Streaming must equal one-shot for EVERY split point. This is the classic
// implementation bug: the partial-buffer path in update() is only exercised when
// a caller feeds data in pieces, so it can stay broken until the first file
// larger than one read buffer. Randomized split points, seeded (SPEC S13).
TEST(sha256_incremental_equals_oneshot) {
  std::mt19937_64 rng(testing::seed());
  for (int trial = 0; trial < 200; trial++) {
    const size_t n = rng() % 4096;
    const std::vector<uint8_t> data = random_bytes(rng, n);
    const Digest32 want = sha256(data);

    const int splits = static_cast<int>(rng() % 5) + 1;
    Sha256 h;
    size_t pos = 0;
    for (int s = 0; s < splits && pos < n; s++) {
      const size_t take = (s == splits - 1) ? (n - pos) : (rng() % (n - pos + 1));
      h.update(data.data() + pos, take);
      pos += take;
    }
    if (pos < n) h.update(data.data() + pos, n - pos);

    TCTX("trial=" << trial << " n=" << n << " splits=" << splits);
    CHECK_EQ(to_hex(h.finish()), to_hex(want));
  }
}

// Byte-at-a-time is the most punishing split pattern: every call takes the
// partial-buffer path, and the 64-byte block boundary is crossed mid-call.
TEST(sha256_byte_at_a_time_across_block_boundaries) {
  std::mt19937_64 rng(testing::seed() ^ 0x5151);
  for (size_t n : {size_t{0}, size_t{1}, size_t{55}, size_t{56}, size_t{57}, size_t{63},
                   size_t{64}, size_t{65}, size_t{127}, size_t{128}, size_t{129}}) {
    TCTX("n=" << n);
    const std::vector<uint8_t> data = random_bytes(rng, n);
    Sha256 h;
    for (size_t i = 0; i < n; i++) h.update(data.data() + i, 1);
    CHECK_EQ(to_hex(h.finish()), to_hex(sha256(data)));
  }
}

// Sanity that we are producing a real hash and not, say, returning the initial
// state: every length 0..256 must give a distinct digest, and a single flipped
// bit must change it.
TEST(sha256_distinctness_and_avalanche) {
  std::vector<std::string> seen;
  std::vector<uint8_t> buf;
  for (size_t n = 0; n <= 256; n++) {
    buf.assign(n, 'x');
    seen.push_back(to_hex(sha256(buf)));
  }
  std::vector<std::string> sorted = seen;
  std::sort(sorted.begin(), sorted.end());
  CHECK_EQ(std::unique(sorted.begin(), sorted.end()) - sorted.begin(),
           static_cast<long>(seen.size()));

  std::mt19937_64 rng(testing::seed() ^ 0xA5A5);
  std::vector<uint8_t> a = random_bytes(rng, 1000);
  const Digest32 da = sha256(a);
  for (int trial = 0; trial < 16; trial++) {
    std::vector<uint8_t> b = a;
    const size_t byte = rng() % b.size();
    b[byte] ^= static_cast<uint8_t>(1u << (rng() % 8));
    TCTX("flip byte=" << byte);
    CHECK_NE(to_hex(sha256(b)), to_hex(da));
  }
}

TEST(hex_round_trip) {
  std::mt19937_64 rng(testing::seed() ^ 0xBEEF);
  for (int i = 0; i < 100; i++) {
    Digest32 d{};
    for (auto& b : d) b = static_cast<uint8_t>(rng() & 0xFF);
    Digest32 back{};
    REQUIRE(from_hex(to_hex(d), back));
    CHECK(d == back);
  }
  // Malformed input must be rejected, not accepted or crashed on (SPEC S9).
  Digest32 out{};
  CHECK(!from_hex("", out));
  CHECK(!from_hex("abc", out));
  CHECK(!from_hex(std::string(64, 'z'), out));
  CHECK(!from_hex(std::string(63, 'a'), out));
  CHECK(!from_hex(std::string(65, 'a'), out));
}

RUN_ALL()
