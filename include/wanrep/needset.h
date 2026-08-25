// The NEED reply of SPEC 3.3: which chunks of the canonical list the target does not have.
//
// WHY A SET OF INTEGERS AND NOT A LIST OF FINGERPRINTS:
//   Both nodes derive the same ordered chunk list from the manifest alone (SPEC 3.3), so
//   the target never has to name a chunk it wants -- it names its *position*. A
//   fingerprint costs 32 bytes; a position costs one to three. On a million-chunk tree
//   that is the difference between a 32 MB reply and a few hundred bytes, and the reply
//   sits on the critical path of one of the two round trips a whole generation costs.
//
// WHY RUN-LENGTH ENCODED, AND WHY THAT IS NOT AN OPTIMIZATION:
//   The two workloads this protocol is built for both produce *runs*, not scatter. A
//   first-ever replication needs every index: one run, four bytes. An incremental
//   replication needs the chunks of the few files that changed -- and a file's chunks are
//   contiguous in the canonical list by construction, because the list is built by
//   walking files in order. So the RLE is not a general-purpose compression guess; it is
//   shaped to the way the canonical list is built. SPEC 3.3's claim that a mostly-
//   unchanged tree costs "a handful of bytes to describe millions of chunks it does not
//   need" is asserted and printed by tests/test_frame.cpp.
//
//   The honest worst case, measured rather than hand-waved: a maximally scattered set
//   (every needed index isolated) costs 2 bytes per index -- one varint for the gap, one
//   for a run length of 1. That is still cheaper than the obvious alternative of a plain
//   varint list, which pays 3 bytes per index once the indices exceed 2^14, and it is
//   1/16th of a fingerprint. So the RLE never loses to what it replaced; it just wins by
//   less on inputs the canonical list does not actually produce.
//
// WHY THE INTERNAL REPRESENTATION IS ALSO RUNS:
//   Storing runs rather than a materialized index vector is what makes decode() safe on
//   hostile input almost for free: decode allocates in proportion to the number of runs
//   in the *input buffer*, never in proportion to the count the input *claims*. A 2-byte
//   payload asserting a run of 2^64 indices costs 16 bytes of memory, not 64 exabytes.
//   Materializing is a separate, explicit act -- to_vector() -- which a caller only
//   performs when it really wants one integer per chunk.
//
// WHY A RUN IS [start, last] INCLUSIVE AND NOT (start, length):
//   Because the index space is the full uint64 range and a length-based run whose last
//   index is 2^64-1 needs a length of 2^64, which does not fit. That is not a theoretical
//   corner: the first version of this file used (start, len), and it (a) rejected the
//   perfectly legal single index 2^64-1 as an overflow, and (b) computed prev_end =
//   start + len, which WRAPPED TO ZERO after such a run and would then have accepted a
//   following run at a *lower* index -- silently producing a runs_ vector that was no
//   longer sorted, which is the invariant contains() and encode() are built on. Inclusive
//   bounds make every one of those computations a subtraction that cannot overflow.
//   docs/CHALLENGES.md carries the full story.
//
// WHY THERE IS STILL A HARD CAP ON THE COUNT (SPEC S7, S12):
//   Because count() feeds arithmetic upstream: the source sizes its send plan from it.
//   A peer that can claim 2^63 needed chunks can make an honest caller try to allocate a
//   plan that large even though *we* never did. So decode() bounds the total index count
//   at kMaxNeedIndices and refuses anything above it. The number is chosen below.
//
// WHAT decode() DELIBERATELY DOES NOT VALIDATE:
//   Whether an index is within range of the canonical chunk list. It cannot -- it has
//   never seen the manifest. That check belongs to the negotiation layer (T7), which
//   knows M, and it is not optional there: an in-cap but out-of-range index is exactly
//   the shape of an out-of-bounds read (SPEC S12). Stated here so the split is a
//   documented contract rather than a hole nobody owns.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "wanrep/result.h"
#include "wanrep/types.h"
#include "wanrep/varint.h"

namespace wanrep {

// The ceiling on how many chunk indices one NEED may claim.
//
// Where the number comes from: an index is one chunk, and a chunk averages kAvgChunk
// (8 KiB), so 2^24 indices is 128 GiB of *newly needed* data inside a single generation
// -- far beyond anything this project claims to replicate in one job, and far beyond
// what fits in the 1 MiB kMaxFrame that a NEED reply travels in anyway (2 bytes is the
// smallest possible run, so a full frame can carry at most ~512 Ki runs). Two orders of
// magnitude of headroom over the real workload, and a bound that keeps every derived
// allocation sane: to_vector() on a set this large is 128 MiB, which is a lot but is
// finite and only happens when a caller explicitly asks for it.
//
// The alternative -- no cap, on the grounds that our own representation is already
// bounded by the input size -- was rejected because it exports the problem: it makes
// every future caller of count() responsible for a check that belongs here, once.
inline constexpr uint64_t kMaxNeedIndices = 1ull << 24;  // 16 777 216

class NeedSet {
 public:
  NeedSet() = default;

  // Indices may arrive in any order and may repeat: the target probes its chunk index
  // per file, in whatever order its workers finish, and asking callers to pre-sort would
  // just move this sort somewhere less visible. Adds are buffered and folded into the
  // run list lazily, so N adds cost one sort rather than N insertions into a sorted
  // vector (which is O(N^2) memmove for random arrival order).
  void add(uint64_t idx) {
    pending_.push_back(idx);
    dirty_ = true;
  }

  bool contains(uint64_t idx) const {
    normalize();
    // Runs are sorted and disjoint, so the only candidate is the last run starting at or
    // before idx.
    auto it = std::upper_bound(runs_.begin(), runs_.end(), idx,
                               [](uint64_t v, const Run& r) { return v < r.start; });
    if (it == runs_.begin()) return false;
    --it;
    return idx <= it->last;
  }

  size_t count() const {
    normalize();
    uint64_t n = 0;
    // (last - start) + 1 can only overflow for a run covering the entire 2^64 index
    // space, which needs 2^64 distinct add() calls to construct and is rejected by the
    // cap on every decode path. Not defended against, because there is no reachable
    // state that produces it -- but note that this is a claim about decode(), not a
    // local property of this loop. It was briefly FALSE: decode() computed its cap check
    // as len_minus_1 + 1, which wrapped for exactly that run and let it through, and the
    // symptom surfaced here as count() == 0 on a non-empty set. Anything that ever
    // relaxes decode()'s cap has to revisit this comment.
    for (const Run& r : runs_) n += (r.last - r.start) + 1;
    return static_cast<size_t>(n);
  }

  bool empty() const {
    normalize();
    return runs_.empty();
  }

  size_t run_count() const {
    normalize();
    return runs_.size();
  }

  // Ascending. The caller pays one uint64 per index here -- see the header comment on
  // why this is a separate step from decoding.
  std::vector<uint64_t> to_vector() const {
    normalize();
    std::vector<uint64_t> out;
    out.reserve(count());
    for (const Run& r : runs_) {
      // Written as a test-at-the-end loop because `i <= r.last` with r.last == 2^64-1
      // never terminates.
      for (uint64_t i = r.start;; i++) {
        out.push_back(i);
        if (i == r.last) break;
      }
    }
    return out;
  }

  // (gap, runlen-1) pairs, both varints, ascending, no terminator -- the payload length
  // from the frame header already says where the encoding ends (SPEC 3.2), so a
  // terminator would be a second, redundant, disagreeable source of truth.
  //
  // `gap` is measured from the END of the previous run, so a dense set costs one pair
  // total; `runlen-1` is stored because a zero-length run is meaningless, which buys a
  // one-byte length for the single-index case that dominates a small edit.
  std::vector<uint8_t> encode() const {
    normalize();
    std::vector<uint8_t> out;
    uint64_t next_free = 0;  // the lowest index not covered by any earlier run
    for (const Run& r : runs_) {
      put_varint(out, r.start - next_free);
      put_varint(out, r.last - r.start);
      if (r.last == UINT64_MAX) break;  // nothing can follow; do not wrap next_free
      next_free = r.last + 1;
    }
    return out;
  }

  // Every failure path below returns before any growth of runs_, and runs_ only ever
  // grows by one entry per two varints actually present in the input -- that is the
  // whole S7 story for this decoder.
  //
  // kMalformed means "these bytes are not a need-set"; kTooLarge means "they are, but
  // they claim more than kMaxNeedIndices". The split is deliberate: the second is a
  // policy limit a future version could raise, the first never becomes valid.
  static Result<NeedSet> decode(ByteSpan in) {
    NeedSet ns;
    size_t pos = 0;
    uint64_t next_free = 0;
    uint64_t total = 0;
    bool first = true;
    bool exhausted = false;  // a previous run reached index 2^64-1

    while (pos < in.size()) {
      // Without this, a run ending at 2^64-1 followed by another pair would have to wrap
      // next_free and could place the next run BELOW its predecessor, breaking the
      // sorted-and-disjoint invariant that contains() and encode() depend on. There is
      // no legal continuation after the top of the index space, so say so.
      if (exhausted) return err(Err::kMalformed, "need-set: run past the end of the index space");

      uint64_t gap = 0, len_minus_1 = 0;
      if (!get_varint(in, pos, gap)) return err(Err::kMalformed, "need-set: bad gap varint");
      if (!get_varint(in, pos, len_minus_1)) {
        return err(Err::kMalformed, "need-set: bad run-length varint");
      }

      // Maximal runs are what make the encoding canonical: a gap of 0 between two runs
      // would mean they are adjacent, i.e. one run spelled as two. Rejecting it means
      // one set has exactly one encoding, so a byte comparison over an encoded need-set
      // means what it appears to mean.
      if (!first && gap == 0) return err(Err::kMalformed, "need-set: adjacent runs");

      if (gap > UINT64_MAX - next_free) return err(Err::kMalformed, "need-set: start overflow");
      const uint64_t start = next_free + gap;
      if (len_minus_1 > UINT64_MAX - start) {
        return err(Err::kMalformed, "need-set: run extends past the index space");
      }
      const uint64_t last = start + len_minus_1;

      // The cap is checked entirely in the len_minus_1 domain, and that is not a style
      // choice -- it is the only form of this check that cannot be walked past.
      //
      // The obvious spelling is `len = len_minus_1 + 1; if (len > kMaxNeedIndices - total)`.
      // It is wrong for exactly one input, and that input is reachable in eleven bytes:
      // gap = 0, len_minus_1 = 2^64-1. Then start = 0, the "run extends past the index
      // space" check above passes (len_minus_1 == UINT64_MAX - 0), and len = 2^64 WRAPS
      // TO ZERO. A length of zero is under every cap, so the run covering all 2^64
      // indices is accepted -- count() then wraps to 0 while empty() is false, and
      // to_vector() walks the entire index space. That is the allocation bomb SPEC S7
      // exists to prevent, arriving through the very check written to prevent it.
      //
      // `remaining` cannot wrap because total <= kMaxNeedIndices is an invariant of the
      // loop (it only ever grows by an amount this check just bounded), and len_minus_1
      // is compared without ever being incremented, so nothing here can overflow.
      // Rejecting when len_minus_1 == remaining is correct at the boundary too: a run
      // always holds len_minus_1 + 1 indices, so it fits only if len_minus_1 < remaining.
      const uint64_t remaining = kMaxNeedIndices - total;
      if (len_minus_1 >= remaining) {
        return err(Err::kTooLarge, "need-set exceeds kMaxNeedIndices");
      }
      total += len_minus_1 + 1;  // safe: len_minus_1 < remaining <= kMaxNeedIndices

      ns.runs_.push_back(Run{start, last});
      if (last == UINT64_MAX) {
        exhausted = true;
      } else {
        next_free = last + 1;
      }
      first = false;
    }

    // A trailing partial pair would have been caught by get_varint above; reaching here
    // means pos == in.size() exactly.
    return ns;
  }

 private:
  struct Run {
    uint64_t start;
    uint64_t last;  // INCLUSIVE -- see the header comment on why not a length
  };

  // Folds pending_ into runs_ and re-establishes the two invariants everything else
  // relies on: runs are sorted by start, and no two are overlapping or adjacent.
  void normalize() const {
    if (!dirty_) return;
    std::vector<Run> all;
    all.reserve(runs_.size() + pending_.size());
    all.insert(all.end(), runs_.begin(), runs_.end());
    for (uint64_t v : pending_) all.push_back(Run{v, v});
    std::sort(all.begin(), all.end(),
              [](const Run& x, const Run& y) { return x.start < y.start; });

    runs_.clear();
    for (const Run& r : all) {
      if (!runs_.empty()) {
        Run& prev = runs_.back();
        // Overlapping or exactly adjacent -> one run. The `== UINT64_MAX` arm is not
        // paranoia: `prev.last + 1` is the only expression here that can wrap, and when
        // prev.last is the top of the space nothing can follow it anyway.
        if (prev.last == UINT64_MAX || r.start <= prev.last + 1) {
          if (r.last > prev.last) prev.last = r.last;
          continue;
        }
      }
      runs_.push_back(r);
    }
    pending_.clear();
    dirty_ = false;
  }

  // Mutable so the read accessors stay const: normalization is a representation detail,
  // not a change to the set the caller sees.
  mutable std::vector<Run> runs_;
  mutable std::vector<uint64_t> pending_;
  mutable bool dirty_ = false;
};

}  // namespace wanrep
