// PROVENANCE: carried over verbatim from project #1 (`dedupe`), with the macro and
// environment-variable prefix renamed. Deliberate reuse: a harness you can read in one
// sitting is worth more than a second, subtly different one, and every test in both
// repositories then fails the same way. SPEC 0 records the carry-over.
//
// Minimal dependency-free test harness.
//
// No gtest, on purpose: this project's whole claim is that it has no hidden
// dependencies, and a framework you can read in one sitting is easier to trust
// than one you install. It gives us exactly what SPEC 6 needs and nothing else:
//
//   TEST(name)            register a test
//   CHECK / CHECK_EQ ...  non-fatal assertion (test keeps running, failure recorded)
//   REQUIRE(cond)         fatal assertion (returns from the test -- use when
//                         continuing would segfault, e.g. after a null/open failure)
//   TCTX(...)             scoped context string, appended to any failure inside
//                         the scope. Turns "CHECK_EQ failed" into "CHECK_EQ failed
//                         [iter=417 size=8193]", which is the difference between a
//                         reproducible bug and a shrug.
//   testing::seed()       reproducible RNG seed, overridable via WANREP_SEED, and
//                         always printed -- SPEC S13.
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

namespace testing {

struct Test {
  const char* name;
  void (*fn)();
};

inline std::vector<Test>& registry() {
  static std::vector<Test> r;
  return r;
}
inline int& failures() {
  static int f = 0;
  return f;
}
inline std::vector<std::string>& context_stack() {
  static std::vector<std::string> c;
  return c;
}

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

// Scoped context. RAII so an early `return` inside a test cannot leave a stale
// frame on the stack.
struct Context {
  explicit Context(std::string s) { context_stack().push_back(std::move(s)); }
  ~Context() { context_stack().pop_back(); }
  Context(const Context&) = delete;
  Context& operator=(const Context&) = delete;
};

// Stringify anything that has operator<<; degrade gracefully for anything else
// rather than failing to compile, so CHECK_EQ works on arbitrary value types.
template <class T>
std::string to_str(const T& v) {
  if constexpr (std::is_same_v<T, bool>) {
    return v ? "true" : "false";
  } else if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, int8_t>) {
    return std::to_string(static_cast<int>(v));  // else it prints as a character
  } else if constexpr (requires(std::ostream& os, const T& x) { os << x; }) {
    std::ostringstream oss;
    oss << v;
    return oss.str();
  } else {
    return "<unprintable>";
  }
}

inline void fail(const char* file, int line, const std::string& msg) {
  std::string ctx;
  for (const auto& c : context_stack()) ctx += (ctx.empty() ? " [" : " ") + c;
  if (!ctx.empty()) ctx += "]";
  std::fprintf(stderr, "  FAIL %s:%d\n    %s%s\n", file, line, msg.c_str(), ctx.c_str());
  failures()++;
}

// Reproducible seed for every randomized test (SPEC S13). Printed once per run so
// a red CI line can be replayed byte-for-byte with WANREP_SEED=<n>.
inline uint64_t seed() {
  static const uint64_t s = [] {
    const char* e = std::getenv("WANREP_SEED");
    return e ? std::strtoull(e, nullptr, 0) : uint64_t{0x9E3779B97F4A7C15ull};
  }();
  return s;
}

inline int run_all(int argc, char** argv) {
  const char* filter = (argc > 1) ? argv[1] : nullptr;
  std::printf("seed: 0x%016llx  (replay with WANREP_SEED=0x%llx)\n",
              static_cast<unsigned long long>(seed()),
              static_cast<unsigned long long>(seed()));
  int failed_tests = 0, ran = 0;
  for (auto& t : registry()) {
    if (filter && std::strstr(t.name, filter) == nullptr) continue;
    ran++;
    const int before = failures();
    const auto t0 = std::chrono::steady_clock::now();
    t.fn();
    const auto ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    const bool ok = (failures() == before);
    std::printf("[%s] %-44s %7.1f ms\n", ok ? "PASS" : "FAIL", t.name, ms);
    if (!ok) failed_tests++;
  }
  std::printf("\n%d tests run, %d failed, %d checks failed\n", ran, failed_tests,
              failures());
  return failed_tests == 0 ? 0 : 1;
}

}  // namespace testing

#define TEST(name)                                       \
  static void name();                                    \
  static ::testing::Registrar reg_##name(#name, name);   \
  static void name()

// __LINE__ must go through two levels of macro expansion; `_tctx_##__LINE__`
// would paste the literal token `__LINE__` and collide on a second use in scope.
#define WANREP_CAT2(a, b) a##b
#define WANREP_CAT(a, b) WANREP_CAT2(a, b)

#define TCTX(expr)                                                        \
  ::testing::Context WANREP_CAT(_tctx_, __LINE__)(([&] {                  \
    std::ostringstream _o;                                                \
    _o << expr;                                                           \
    return _o.str();                                                      \
  })())

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) ::testing::fail(__FILE__, __LINE__, "CHECK(" #cond ")");    \
  } while (0)

// Fatal: stop this test. For preconditions whose failure would make the rest of
// the test crash rather than merely fail.
#define REQUIRE(cond)                                                            \
  do {                                                                           \
    if (!(cond)) {                                                               \
      ::testing::fail(__FILE__, __LINE__, "REQUIRE(" #cond ") -- aborting test"); \
      return;                                                                    \
    }                                                                            \
  } while (0)

#define WANREP_CMP(a, b, op, label)                                            \
  do {                                                                         \
    const auto& _a = (a);                                                      \
    const auto& _b = (b);                                                      \
    if (!(_a op _b)) {                                                         \
      ::testing::fail(__FILE__, __LINE__,                                      \
                      label "(" #a ", " #b ")  got: " + ::testing::to_str(_a) + \
                          "  vs  " + ::testing::to_str(_b));                   \
    }                                                                          \
  } while (0)

#define CHECK_EQ(a, b) WANREP_CMP(a, b, ==, "CHECK_EQ")
#define CHECK_NE(a, b) WANREP_CMP(a, b, !=, "CHECK_NE")
#define CHECK_LT(a, b) WANREP_CMP(a, b, <, "CHECK_LT")
#define CHECK_LE(a, b) WANREP_CMP(a, b, <=, "CHECK_LE")
#define CHECK_GT(a, b) WANREP_CMP(a, b, >, "CHECK_GT")
#define CHECK_GE(a, b) WANREP_CMP(a, b, >=, "CHECK_GE")

#define RUN_ALL() \
  int main(int argc, char** argv) { return ::testing::run_all(argc, argv); }
