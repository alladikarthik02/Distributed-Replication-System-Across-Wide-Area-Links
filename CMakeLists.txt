cmake_minimum_required(VERSION 3.22)
project(wanrep CXX)

set(CMAKE_CXX_STANDARD 20)          # std::span, <bit>, jthread, requires-expressions
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)       # -std=c++20, never -std=gnu++20: portability is a claim we make

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)  # -O2 -g: we benchmark optimized code, but keep symbols
endif()

# -Werror=unused-result is not style, it is SPEC S11: an ignored write()/fsync()/read()
# return value is exactly how a replication engine loses data silently. On a socket it
# is worse than on a file, because short writes are the normal case, not the rare one.
add_compile_options(
  -Wall -Wextra -Wpedantic -Wshadow
  -Werror=unused-result
  -Werror=return-type
)

# Sanitizer configuration, selected by scripts/check.sh (SPEC S7, S8, S9, S14).
#   -DWANREP_SANITIZE=address  -> ASan + UBSan
#   -DWANREP_SANITIZE=thread   -> TSan
set(WANREP_SANITIZE "none" CACHE STRING "none | address | thread")
if(WANREP_SANITIZE STREQUAL "address")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
elseif(WANREP_SANITIZE STREQUAL "thread")
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=thread)
elseif(NOT WANREP_SANITIZE STREQUAL "none")
  message(FATAL_ERROR "WANREP_SANITIZE must be none|address|thread, got '${WANREP_SANITIZE}'")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/tests)

enable_testing()

# One line per suite. Keeps later tasks from touching build plumbing.
function(wanrep_test name)
  add_executable(${name} tests/${name}.cpp ${ARGN})
  target_link_libraries(${name} PRIVATE pthread)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

# --- T0: foundations ----------------------------------------------------------
wanrep_test(test_harness)

# --- T1: content primitives ---------------------------------------------------
wanrep_test(test_sha256)
wanrep_test(test_crc32c)
wanrep_test(test_chunker)

# --- T2: wire protocol --------------------------------------------------------
wanrep_test(test_frame)

# --- T3: in-transit compression -----------------------------------------------
wanrep_test(test_compress)

# --- T4: lock-free queues -----------------------------------------------------
wanrep_test(test_queues)

# --- T5: link layer -----------------------------------------------------------
wanrep_test(test_link)

# --- T6: target store ---------------------------------------------------------
wanrep_test(test_store)

# --- T7: manifests and negotiation --------------------------------------------
wanrep_test(test_negotiate)

# --- T8: end-to-end replication -----------------------------------------------
wanrep_test(test_replicate)

# --- T9: resumable transfers --------------------------------------------------
wanrep_test(test_session)
wanrep_test(test_resume)

# --- T10: fault injection -----------------------------------------------------
wanrep_test(test_faults)

# The CLI.
add_executable(wanrep src/main.cpp)
target_link_libraries(wanrep PRIVATE pthread)

# Tools. faultrunner forks real target processes and kills them, so it is a TOOL rather
# than a ctest case -- it is run explicitly and prints a matrix.
add_executable(faultrunner tools/faultrunner.cpp)
target_link_libraries(faultrunner PRIVATE pthread)

# Benchmarks are built, not run, by ctest -- they are measurements, not pass/fail gates.
# Run them explicitly:  ./build-none/bench_chunker
add_executable(bench_hash bench/bench_hash.cpp)
add_executable(bench_chunker bench/bench_chunker.cpp)
add_executable(bench_lz bench/bench_lz.cpp)
add_executable(bench_queues bench/bench_queues.cpp)
target_link_libraries(bench_queues PRIVATE pthread)
add_executable(bench_wire bench/bench_wire.cpp)
target_link_libraries(bench_wire PRIVATE pthread)
