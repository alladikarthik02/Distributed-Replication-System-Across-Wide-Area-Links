// The replication protocol: what the two nodes actually say to each other (SPEC 3.2, 3.3,
// 3.5, 3.6, 3.7).
//
// ROUND TRIPS, NOT BYTES, ARE THE WAN ENEMY (SPEC 3.2):
//   At 100 Mbit/s with a 100 ms RTT the bandwidth-delay product is 1.25 MB -- that much
//   must be in flight to keep the link busy. A protocol that asks "do you need this
//   chunk?" and waits moves one 8 KiB chunk per round trip: ~82 KB/s, 0.65% of the link,
//   while looking perfect on loopback. So: ONE batched negotiation per generation, and
//   chunk payloads streamed with NO per-chunk acknowledgement. CHECKPOINT frames flow
//   back advisorily and are never waited on.
//
// THE FIVE ROUND TRIPS OF A FULL GENERATION:
//   HELLO/HELLO_ACK, SESSION_START+MANIFEST -> NEED, ...stream chunks..., GEN_COMMIT ->
//   COMMIT_ACK. Independent of dataset size. A resumed job replaces the middle with a
//   single SESSION_RESUME/SESSION_ACK.
//
// EVERY BYTE FROM THE PEER IS HOSTILE (SPEC S7, S12, S17). Lengths are bounded before
// they size anything, the manifest is validated before it is used, and every chunk is
// re-hashed before it is stored -- the target's correctness never depends on the source
// being correct.
#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "wanrep/frame.h"
#include "wanrep/lz.h"
#include "wanrep/manifest.h"
#include "wanrep/mpmc_queue.h"
#include "wanrep/negotiate.h"
#include "wanrep/session.h"
#include "wanrep/target_store.h"
#include "wanrep/varint.h"

namespace wanrep {

inline constexpr uint32_t kProtocolVersion = 1;

// kFlagLastSlice is declared in types.h: blobs (manifests, need sets) that exceed one
// frame are sliced across several, each carrying its byte offset in `seq`, and the final
// slice sets that bit.

// Receive-side caps. Both bound memory against a peer that lies about sizes (SPEC S10).
// 64 MiB of manifest is ~1.8M chunk refs, i.e. a tree of roughly 14 GiB at 8 KiB chunks:
// generous for this project and finite, which is the property that matters.
inline constexpr size_t kMaxManifestBytes = 64u << 20;
inline constexpr size_t kMaxNeedBytes = 16u << 20;
inline constexpr size_t kMaxBatchRaw = 1u << 20;  // must stay <= kMaxFrame

// Payload bytes per CHUNKS batch before compression. SPEC 3.4: an 8 KiB chunk compressed
// alone wastes the dictionary; batching lets the matcher find cross-chunk redundancy,
// which is common in backup data. Tuned with a measurement in bench/bench_lz.
inline constexpr size_t kDefaultBatchBytes = 256u << 10;

struct JobStats {
  uint64_t wire_bytes_out = 0;      // THE authoritative bandwidth number (Link::bytes_out)
  uint64_t wire_bytes_in = 0;
  uint64_t logical_bytes = 0;       // size of the source tree
  uint64_t payload_bytes_sent = 0;  // chunk bytes before compression
  uint64_t compressed_bytes_sent = 0;
  uint64_t manifest_bytes_sent = 0;
  size_t chunks_total = 0;
  size_t chunks_sent = 0;
  size_t chunks_skipped = 0;        // already on the target
  size_t files_total = 0;
  size_t files_unchanged = 0;
  size_t frames_out = 0;
  size_t frames_in = 0;
  size_t round_trips = 0;
  bool resumed = false;
  uint64_t resumed_from = 0;
};

namespace proto {

inline void put_bytes(std::vector<uint8_t>& o, ByteSpan b) {
  put_varint(o, b.size());
  o.insert(o.end(), b.begin(), b.end());
}
inline void put_str(std::vector<uint8_t>& o, const std::string& s) {
  put_bytes(o, as_bytes(std::string_view(s)));
}
inline bool get_str(ByteSpan in, size_t& pos, std::string& out, size_t cap) {
  uint64_t n = 0;
  if (!get_varint(in, pos, n) || n > cap || pos + n > in.size()) return false;
  out.assign(reinterpret_cast<const char*>(in.data() + pos), static_cast<size_t>(n));
  pos += static_cast<size_t>(n);
  return true;
}
inline bool get_digest(ByteSpan in, size_t& pos, Digest32& out) {
  if (pos + 32 > in.size()) return false;
  std::memcpy(out.data(), in.data() + pos, 32);
  pos += 32;
  return true;
}

// Streams a blob across as many frames as it needs. The last slice sets kFlagLastSlice,
// so the receiver never has to be told a total up front -- which means it never has to
// trust one.
inline Result<void> send_blob(FrameWriter& w, FrameType type, ByteSpan blob) {
  const size_t slice = kMaxFrame - 1024;  // headroom under the hard frame cap
  size_t off = 0;
  do {
    const size_t n = std::min(slice, blob.size() - off);
    const uint8_t flags = (off + n >= blob.size()) ? kFlagLastSlice : 0;
    WANREP_TRY(w.write(type, off, blob.subspan(off, n), flags));
    off += n;
  } while (off < blob.size());
  return {};
}

// Collects a sliced blob. `cap` bounds the total BEFORE the allocation grows (SPEC S7):
// a peer cannot make us buffer more than we agreed to.
inline Result<std::vector<uint8_t>> recv_blob(FrameReader& r, FrameType expect, size_t cap,
                                              size_t* frames = nullptr) {
  std::vector<uint8_t> out;
  for (;;) {
    auto f = r.next();
    if (!f.ok()) return f.error();
    if (frames) (*frames)++;
    if (f->type != expect) {
      return err(Err::kProtocol, "expected frame type " +
                                     std::to_string(static_cast<int>(expect)) + ", got " +
                                     std::to_string(static_cast<int>(f->type)));
    }
    if (f->seq != out.size()) return err(Err::kProtocol, "blob slice out of order");
    if (out.size() + f->payload.size() > cap) return err(Err::kTooLarge, "blob exceeds cap");
    out.insert(out.end(), f->payload.begin(), f->payload.end());
    if (f->flags & kFlagLastSlice) break;
  }
  return out;
}

// A CHUNKS batch payload: a run of (varint length, bytes) for chunks at consecutive plan
// indices starting at the frame's seq. The count is implied by parsing to the end, so a
// truncated batch cannot claim more chunks than it carries.
inline void encode_batch(std::vector<uint8_t>& out, const std::vector<std::vector<uint8_t>>& chunks) {
  for (const auto& c : chunks) {
    put_varint(out, c.size());
    out.insert(out.end(), c.begin(), c.end());
  }
}

inline Result<std::vector<ByteSpan>> decode_batch(ByteSpan in) {
  std::vector<ByteSpan> out;
  size_t pos = 0;
  while (pos < in.size()) {
    uint64_t n = 0;
    if (!get_varint(in, pos, n)) return err(Err::kMalformed, "batch length varint");
    if (n == 0 || n > kMaxChunk) return err(Err::kMalformed, "batch chunk length");
    if (pos + n > in.size()) return err(Err::kMalformed, "batch truncated");
    out.push_back(in.subspan(pos, static_cast<size_t>(n)));
    pos += static_cast<size_t>(n);
  }
  return out;
}

// Compresses if it helps, sends raw if it does not. SPEC S14's never-expand rule lives
// here, at the only place that decides what actually goes on the wire.
inline Result<void> send_batch(FrameWriter& w, uint64_t seq, ByteSpan raw, bool compress,
                               uint64_t* compressed_bytes) {
  if (raw.size() > kMaxBatchRaw) return err(Err::kTooLarge, "batch too large");
  if (compress) {
    std::vector<uint8_t> packed(lz::max_compressed_size(raw.size()));
    const size_t n = lz::compress(raw, packed.data(), packed.size());
    if (n > 0 && n < raw.size()) {
      *compressed_bytes += n;
      return w.write(FrameType::kChunks, seq, ByteSpan(packed.data(), n), kFlagCompressed,
                     static_cast<uint32_t>(raw.size()));
    }
  }
  *compressed_bytes += raw.size();
  return w.write(FrameType::kChunks, seq, raw, 0, static_cast<uint32_t>(raw.size()));
}

inline Result<std::vector<uint8_t>> unpack_batch(const Frame& f) {
  if ((f.flags & kFlagCompressed) == 0) return f.payload;
  // raw_len was already bounded against kMaxFrame by the frame reader (SPEC S7), so this
  // allocation is bounded before it happens.
  std::vector<uint8_t> out(f.raw_len);
  auto n = lz::decompress(ByteSpan(f.payload.data(), f.payload.size()), out.data(), out.size());
  if (!n.ok()) return n.error();
  if (*n != out.size()) return err(Err::kMalformed, "decompressed size disagrees with raw_len");
  return out;
}

}  // namespace proto

// ---------------------------------------------------------------------------
// Target side
// ---------------------------------------------------------------------------

class TargetServer {
 public:
  explicit TargetServer(TargetStore& store, SessionJournal& sessions)
      : store_(store), sessions_(sessions) {}

  // Serves exactly one connection to completion, or until it breaks. A broken link is a
  // normal outcome, not an exception: the source reconnects and resumes (SPEC 3.7).
  Result<void> serve(Link& link) {
    FrameReader reader(link);
    FrameWriter writer(link);

    // --- handshake ---
    auto hello = reader.next();
    if (!hello.ok()) return hello.error();
    if (hello->type != FrameType::kHello) return err(Err::kProtocol, "expected HELLO");
    {
      size_t pos = 0;
      const ByteSpan p(hello->payload.data(), hello->payload.size());
      uint64_t ver = 0, mn = 0, av = 0, mx = 0;
      if (!get_varint(p, pos, ver) || !get_varint(p, pos, mn) || !get_varint(p, pos, av) ||
          !get_varint(p, pos, mx)) {
        return err(Err::kMalformed, "HELLO");
      }
      if (ver != kProtocolVersion) {
        (void)send_error(writer, Err::kUnsupported, "protocol version");
        return err(Err::kUnsupported, "peer speaks protocol " + std::to_string(ver));
      }
      // Chunk parameters are part of the handshake, not a local tunable: disagreeing
      // means the two nodes compute different boundaries, every fingerprint differs, and
      // the set difference silently degrades to "send everything" (types.h).
      if (mn != kMinChunk || av != kAvgChunk || mx != kMaxChunk) {
        (void)send_error(writer, Err::kUnsupported, "chunk parameters differ");
        return err(Err::kUnsupported, "chunk parameter mismatch");
      }
    }
    {
      std::vector<uint8_t> ack;
      put_varint(ack, kProtocolVersion);
      WANREP_TRY(writer.write(FrameType::kHelloAck, 0, ByteSpan(ack.data(), ack.size())));
    }
    if (WANREP_FAULT(FaultPoint::kAfterHello) == FaultKind::kDropLink) {
      link.close();
      return err(Err::kFaultInjected, "after_hello");
    }

    // --- session setup: either a fresh job or a resume ---
    auto first = reader.next();
    if (!first.ok()) return first.error();

    if (first->type == FrameType::kSessionResume) return resume(link, reader, writer, *first);
    if (first->type != FrameType::kSessionStart) return err(Err::kProtocol, "expected SESSION_START/RESUME");
    return fresh(link, reader, writer, *first);
  }

 private:
  struct Live {
    std::string session_id;
    std::string dataset;
    uint64_t generation = 0;
    Digest32 manifest_digest{};
    Manifest manifest;
    std::vector<Digest32> canonical;
    std::vector<uint64_t> plan;  // canonical index of each plan position
    std::unique_ptr<HighWaterTracker> tracker;
    uint64_t bytes_received = 0;
    uint64_t since_checkpoint = 0;
  };

  // The most recent committed manifest for a dataset, or null if there is none. Used only
  // to ATTRIBUTE savings (unchanged files vs chunk dedup) -- the store, not this, decides
  // what is actually needed. See negotiate.h.
  const Manifest* load_previous(const std::string& dataset, Manifest& storage) {
    auto latest = store_.generations().latest_generation(dataset);
    if (!latest.ok()) return nullptr;
    auto pb = store_.generations().manifest_bytes(dataset, *latest);
    if (!pb.ok()) return nullptr;
    auto pm = Manifest::decode(ByteSpan(pb->data(), pb->size()));
    if (!pm.ok()) return nullptr;
    storage = std::move(*pm);
    return &storage;
  }

  static Result<void> send_error(FrameWriter& w, Err code, const std::string& msg) {
    std::vector<uint8_t> p;
    put_varint(p, static_cast<uint64_t>(code));
    proto::put_str(p, msg);
    return w.write(FrameType::kError, 0, ByteSpan(p.data(), p.size()));
  }

  Result<void> fresh(Link& link, FrameReader& reader, FrameWriter& writer, const Frame& start) {
    Live s;
    {
      size_t pos = 0;
      const ByteSpan p(start.payload.data(), start.payload.size());
      uint64_t gen = 0;
      if (!proto::get_str(p, pos, s.dataset, 128) || !get_varint(p, pos, gen) ||
          !proto::get_digest(p, pos, s.manifest_digest)) {
        return err(Err::kMalformed, "SESSION_START");
      }
      s.generation = gen;
      if (!valid_dataset_name(s.dataset)) return err(Err::kInvalidArgument, "dataset name");
    }

    // --- manifest ---
    size_t frames = 0;
    auto blob = proto::recv_blob(reader, FrameType::kManifest, kMaxManifestBytes, &frames);
    if (!blob.ok()) return blob.error();
    if (WANREP_FAULT(FaultPoint::kAfterManifest) == FaultKind::kDropLink) {
      link.close();
      return err(Err::kFaultInjected, "after_manifest");
    }
    const ByteSpan mb(blob->data(), blob->size());
    // The source's claim about its own manifest must match the bytes it sent, or a
    // resumed session could be matched against a different tree.
    if (sha256(mb) != s.manifest_digest) return err(Err::kProtocol, "manifest digest mismatch");
    auto m = Manifest::decode(mb);
    if (!m.ok()) return m.error();
    if (m->dataset != s.dataset || m->generation != s.generation) {
      return err(Err::kProtocol, "manifest disagrees with SESSION_START");
    }
    s.manifest = std::move(*m);

    // --- negotiate: the set difference (SPEC 3.3) ---
    Manifest prev_storage;
    const Manifest* previous = load_previous(s.dataset, prev_storage);
    const auto neg = negotiate(s.manifest, previous, store_.chunks());
    s.canonical = canonical_chunk_list(s.manifest);
    s.plan = neg.need.to_vector();

    s.session_id = SessionJournal::session_id_for(s.dataset, s.generation, s.manifest_digest);
    const auto need_bytes = neg.need.encode();
    WANREP_TRY(sessions_.save_blobs(s.session_id, mb, ByteSpan(need_bytes.data(), need_bytes.size())));
    s.tracker = std::make_unique<HighWaterTracker>(s.plan.size(), 0);
    WANREP_TRY(save_checkpoint(s));

    // --- reply NEED, prefixed with the session id so the source can resume ---
    {
      std::vector<uint8_t> head;
      proto::put_str(head, s.session_id);
      put_varint(head, 0);  // high-water: a fresh session starts at zero
      WANREP_TRY(writer.write(FrameType::kSessionAck, 0, ByteSpan(head.data(), head.size())));
    }
    WANREP_TRY(proto::send_blob(writer, FrameType::kNeed,
                               ByteSpan(need_bytes.data(), need_bytes.size())));
    if (WANREP_FAULT(FaultPoint::kAfterNeed) == FaultKind::kDropLink) {
      link.close();
      return err(Err::kFaultInjected, "after_need");
    }
    return transfer(link, reader, writer, s);
  }

  Result<void> resume(Link& link, FrameReader& reader, FrameWriter& writer, const Frame& rq) {
    std::string id;
    {
      size_t pos = 0;
      const ByteSpan p(rq.payload.data(), rq.payload.size());
      if (!proto::get_str(p, pos, id, 64)) return err(Err::kMalformed, "SESSION_RESUME");
    }
    if (WANREP_FAULT(FaultPoint::kMidResumeHandshake) == FaultKind::kDropLink) {
      link.close();
      return err(Err::kFaultInjected, "mid_resume_handshake");
    }

    // Any failure to reload is answered with "not found", never with an error: the source
    // then falls back to re-negotiation, which is correct and costs two round trips. A
    // lost checkpoint must never be able to fail a job (SPEC 3.7).
    auto st = sessions_.load(id);
    auto mb = st.ok() ? sessions_.load_manifest_blob(id, kMaxManifestBytes)
                      : Result<std::vector<uint8_t>>(err(Err::kNotFound, "no session"));
    auto nb = mb.ok() ? sessions_.load_need_blob(id, kMaxNeedBytes)
                      : Result<std::vector<uint8_t>>(err(Err::kNotFound, "no session"));
    if (!st.ok() || !mb.ok() || !nb.ok()) {
      std::vector<uint8_t> p;
      proto::put_str(p, "");  // empty id == not found
      put_varint(p, 0);
      WANREP_TRY(writer.write(FrameType::kSessionAck, 0, ByteSpan(p.data(), p.size())));
      return err(Err::kNotFound, "session not resumable");
    }

    auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
    if (!m.ok()) return m.error();
    (void)nb;  // the stored need set is kept only for forensics; see below

    Live s;
    s.session_id = id;
    s.dataset = st->dataset;
    s.generation = st->generation;
    s.manifest_digest = st->manifest_digest;
    s.manifest = std::move(*m);
    s.canonical = canonical_chunk_list(s.manifest);
    s.bytes_received = st->bytes_received;

    // RESUMING IS JUST RE-NEGOTIATING WITHOUT RE-SENDING THE MANIFEST
    // (docs/CHALLENGES.md B7).
    //
    // The obvious design -- keep the original plan, remember how far it got, restart there
    // -- was wrong twice over. Batches are compressed on several threads and therefore
    // arrive OUT OF ORDER, so one missing early batch pins the contiguous mark near zero
    // and "resume" re-sends everything after it, INCLUDING chunks the target already
    // holds. And checkpoints are written every 8 MiB, so a smaller transfer resumed from
    // zero outright. Measured: the fast path was slower than the session-deleted fallback,
    // which re-ran the set difference and correctly skipped what had landed. The
    // optimization was losing to the thing it was optimizing.
    //
    // So resume does what the fallback does: recompute the set difference against the
    // store, which is authoritative. Everything already received drops out no matter what
    // order it arrived in, no matter when the last checkpoint was, and even if a chunk was
    // lost to corruption since (it is simply re-requested). The plan is rebuilt from that
    // fresh need set on both sides, so it needs no stability guarantee at all -- which
    // deletes the whole class of bug rather than patching it.
    //
    // What resume still saves is the expensive half: the manifest is already here, so it
    // is not re-sent. On a large tree that IS the cost (SPEC 8.3).
    Manifest prev_storage;
    const Manifest* previous = load_previous(s.dataset, prev_storage);
    const auto neg = negotiate(s.manifest, previous, store_.chunks());
    s.plan = neg.need.to_vector();
    const uint64_t already = (st->plan_size > s.plan.size()) ? st->plan_size - s.plan.size() : 0;
    s.tracker = std::make_unique<HighWaterTracker>(s.plan.size(), 0);

    const auto need_bytes = neg.need.encode();
    WANREP_TRY(sessions_.save_blobs(id, ByteSpan(mb->data(), mb->size()),
                                    ByteSpan(need_bytes.data(), need_bytes.size())));
    WANREP_TRY(save_checkpoint(s));

    std::vector<uint8_t> p;
    proto::put_str(p, id);
    put_varint(p, already);  // how many plan entries this resume skipped, for reporting
    WANREP_TRY(writer.write(FrameType::kSessionAck, 0, ByteSpan(p.data(), p.size())));
    WANREP_TRY(proto::send_blob(writer, FrameType::kNeed,
                               ByteSpan(need_bytes.data(), need_bytes.size())));
    return transfer(link, reader, writer, s);
  }

  Result<void> transfer(Link& link, FrameReader& reader, FrameWriter& writer, Live& s) {
    for (;;) {
      auto f = reader.next();
      if (!f.ok()) return f.error();

      if (f->type == FrameType::kChunks) {
        WANREP_TRY(accept_batch(writer, s, *f));
        continue;
      }
      if (f->type == FrameType::kGenCommit) {
        return commit(link, writer, s, *f);
      }
      if (f->type == FrameType::kBye) return {};
      if (f->type == FrameType::kError) return err(Err::kProtocol, "peer reported an error");
      return err(Err::kProtocol, "unexpected frame during transfer");
    }
  }

  Result<void> accept_batch(FrameWriter& writer, Live& s, const Frame& f) {
    auto raw = proto::unpack_batch(f);
    if (!raw.ok()) return raw.error();
    auto chunks = proto::decode_batch(ByteSpan(raw->data(), raw->size()));
    if (!chunks.ok()) return chunks.error();

    const uint64_t seq = f.seq;
    if (seq + chunks->size() > s.plan.size()) return err(Err::kProtocol, "batch past plan end");

    for (size_t i = 0; i < chunks->size(); i++) {
      const uint64_t plan_pos = seq + i;
      const uint64_t canon = s.plan[plan_pos];
      if (canon >= s.canonical.size()) return err(Err::kCorrupt, "plan index out of range");
      // SPEC S17, at the only place it can be enforced: the chunk must hash to the name
      // the PLAN says belongs at this position. This catches a mislabelled chunk, a
      // reordered batch, and a source that is simply wrong -- all identically.
      WANREP_TRY(store_.chunks().put(s.canonical[canon], (*chunks)[i]));
      s.bytes_received += (*chunks)[i].size();
      s.since_checkpoint += (*chunks)[i].size();
    }
    WANREP_TRY(s.tracker->mark_range(seq, chunks->size()));

    if (s.since_checkpoint >= kCheckpointBytes) {
      WANREP_TRY(store_.chunks().sync());  // durable BEFORE the mark that claims it is
      WANREP_TRY(save_checkpoint(s));
      s.since_checkpoint = 0;
    }
    // NOTE: no CHECKPOINT frame is sent back, and that is a deliberate change from the
    // original design (SPEC 3.2 listed it as advisory, T -> S).
    //
    // The source never needs it: on reconnect the target reports its high-water mark in
    // SESSION_ACK, which is the only moment the number is actually used. Meanwhile
    // sending it created a real deadlock: the source streams chunks without reading, so
    // unread CHECKPOINT frames accumulate in the target's send buffer; once that buffer
    // fills, the target blocks in write(), stops reading chunks, and the source blocks in
    // write() too. At one frame per 8 MiB and a 64 KiB buffer that is ~13 GiB of transfer
    // away -- rare enough to pass every test and certain enough to happen in production.
    // Removing the frame removes the entire deadlock class for zero loss of function.
    (void)writer;
    return {};
  }

  Result<void> commit(Link& link, FrameWriter& writer, Live& s, const Frame& f) {
    size_t pos = 0;
    const ByteSpan p(f.payload.data(), f.payload.size());
    uint64_t gen = 0;
    Digest32 digest{};
    if (!get_varint(p, pos, gen) || !proto::get_digest(p, pos, digest)) {
      return err(Err::kMalformed, "GEN_COMMIT");
    }
    if (gen != s.generation || digest != s.manifest_digest) {
      return err(Err::kProtocol, "GEN_COMMIT does not match this session");
    }
    // The transfer is only complete when every plan position is CONTIGUOUSLY accounted
    // for. "Highest seen" would let a gap through and commit a generation with a hole.
    if (!s.tracker->complete()) {
      return err(Err::kProtocol, "commit requested with " +
                                     std::to_string(s.plan.size() - s.tracker->contiguous()) +
                                     " chunks still missing");
    }

    // SPEC S4's ordering, and the only durable sequence correctness depends on.
    WANREP_TRY(store_.chunks().sync());
    const auto mb = s.manifest.encode();
    WANREP_TRY(store_.generations().commit(s.dataset, s.generation,
                                           ByteSpan(mb.data(), mb.size())));

    if (WANREP_FAULT(FaultPoint::kAfterCommitBeforeAck) == FaultKind::kDropLink) {
      link.close();
      // Committed, but the source does not know. Its retry must succeed -- which it does,
      // because commit() is idempotent (SPEC 3.5).
      return err(Err::kFaultInjected, "after_commit_before_ack");
    }

    WANREP_TRY(sessions_.erase(s.session_id));
    std::vector<uint8_t> ack;
    put_varint(ack, s.generation);
    return writer.write(FrameType::kCommitAck, 0, ByteSpan(ack.data(), ack.size()));
  }

  Result<void> save_checkpoint(Live& s) {
    SessionState st;
    st.session_id = s.session_id;
    st.dataset = s.dataset;
    st.generation = s.generation;
    st.manifest_digest = s.manifest_digest;
    st.plan_size = s.plan.size();
    st.high_water = s.tracker->contiguous();
    st.bytes_received = s.bytes_received;
    return sessions_.save(st);
  }

  TargetStore& store_;
  SessionJournal& sessions_;
};

// ---------------------------------------------------------------------------
// Source side
// ---------------------------------------------------------------------------
//
// THE PIPELINE (SPEC 3.6). Work moves forward through bounded lock-free queues:
//
//   reader thread ──[MpmcQueue]──> compressor x N ──[MpmcQueue]──> sender (this thread)
//
// The sender is a single thread that OWNS the socket, which removes any need for a lock
// around write() and guarantees frames are never interleaved. It costs nothing: T1
// measured chunk+SHA-256 at 966 MB/s on one thread, 77x a 100 Mbit/s link, so the
// expensive work is upstream and already done by the time bytes reach the wire.
//
// The queues are BOUNDED, which is the backpressure that keeps memory constant regardless
// of tree size (SPEC S10, R2.6). A producer facing a full queue yields rather than
// growing a buffer -- that waiting path is not lock-free and is not claimed to be; the
// claim is "lock-free queues on the hot path", and the hot path is the
// uncontended push/pop, which takes no lock.
class SourceJob {
 public:
  struct Options {
    std::string dataset = "default";
    uint64_t generation = 0;
    size_t batch_bytes = kDefaultBatchBytes;
    bool compress = true;
    int compressor_threads = 2;
    std::string resume_session_id;  // non-empty: try the fast resume path first
  };

  // Runs one generation over one link. `pre_scanned` lets a caller reuse a manifest across
  // a reconnect instead of re-walking the tree.
  static Result<JobStats> run(Link& link, const std::string& tree, const Options& opt,
                              const Manifest* pre_scanned = nullptr,
                              std::string* out_session_id = nullptr) {
    JobStats stats;
    Manifest local;
    if (pre_scanned != nullptr) {
      local = *pre_scanned;
    } else {
      auto m = scan_tree(tree, opt.dataset, opt.generation);
      if (!m.ok()) return m.error();
      local = std::move(*m);
    }
    stats.logical_bytes = local.logical_bytes();
    stats.files_total = local.files.size();

    FrameWriter writer(link);
    FrameReader reader(link);

    // --- handshake ---
    {
      std::vector<uint8_t> p;
      put_varint(p, kProtocolVersion);
      put_varint(p, kMinChunk);
      put_varint(p, kAvgChunk);
      put_varint(p, kMaxChunk);
      WANREP_TRY(writer.write(FrameType::kHello, 0, ByteSpan(p.data(), p.size())));
    }
    {
      auto ack = reader.next();
      if (!ack.ok()) return ack.error();
      if (ack->type == FrameType::kError) return err(Err::kUnsupported, "peer rejected HELLO");
      if (ack->type != FrameType::kHelloAck) return err(Err::kProtocol, "expected HELLO_ACK");
      stats.round_trips++;
    }

    const auto manifest_bytes = local.encode();
    const Digest32 manifest_digest =
        sha256(ByteSpan(manifest_bytes.data(), manifest_bytes.size()));

    // --- session: fast resume if we were given an id, else a fresh negotiation ---
    std::string session_id;
    uint64_t high_water = 0;
    bool resumed = false;

    if (!opt.resume_session_id.empty()) {
      std::vector<uint8_t> p;
      proto::put_str(p, opt.resume_session_id);
      WANREP_TRY(writer.write(FrameType::kSessionResume, 0, ByteSpan(p.data(), p.size())));
      auto ack = reader.next();
      if (!ack.ok()) return ack.error();
      if (ack->type != FrameType::kSessionAck) return err(Err::kProtocol, "expected SESSION_ACK");
      size_t pos = 0;
      const ByteSpan ap(ack->payload.data(), ack->payload.size());
      std::string id;
      uint64_t hw = 0;
      if (!proto::get_str(ap, pos, id, 64)) return err(Err::kMalformed, "SESSION_ACK");
      if (!id.empty()) {
        // `hw` is how many plan entries the target skipped because it already had them --
        // reporting only. The plan that follows is already the reduced one, so this
        // attempt starts at its beginning.
        if (!get_varint(ap, pos, hw)) return err(Err::kMalformed, "SESSION_ACK skipped count");
        session_id = id;
        high_water = 0;
        stats.resumed_from = hw;
        resumed = true;
      }
      stats.round_trips++;
      if (!resumed) {
        // The target does not know this session. Not an error: fall through to a fresh
        // negotiation, which still will not re-send chunks it already holds (SPEC 3.7).
        return err(Err::kNotFound, "session not resumable; caller should retry fresh");
      }
    } else {
      std::vector<uint8_t> p;
      proto::put_str(p, opt.dataset);
      put_varint(p, opt.generation);
      p.insert(p.end(), manifest_digest.begin(), manifest_digest.end());
      WANREP_TRY(writer.write(FrameType::kSessionStart, 0, ByteSpan(p.data(), p.size())));
      WANREP_TRY(proto::send_blob(writer, FrameType::kManifest,
                                 ByteSpan(manifest_bytes.data(), manifest_bytes.size())));
      stats.manifest_bytes_sent = manifest_bytes.size();

      auto ack = reader.next();
      if (!ack.ok()) return ack.error();
      if (ack->type == FrameType::kError) return err(Err::kProtocol, "peer rejected the session");
      if (ack->type != FrameType::kSessionAck) return err(Err::kProtocol, "expected SESSION_ACK");
      size_t pos = 0;
      const ByteSpan ap(ack->payload.data(), ack->payload.size());
      if (!proto::get_str(ap, pos, session_id, 64)) return err(Err::kMalformed, "SESSION_ACK");
      stats.round_trips++;
    }
    if (out_session_id != nullptr) *out_session_id = session_id;
    stats.resumed = resumed;

    // --- the need set (both paths end here) ---
    auto need_bytes = proto::recv_blob(reader, FrameType::kNeed, kMaxNeedBytes, &stats.frames_in);
    if (!need_bytes.ok()) return need_bytes.error();
    auto need = NeedSet::decode(ByteSpan(need_bytes->data(), need_bytes->size()));
    if (!need.ok()) return need.error();

    const auto canonical = canonical_chunk_list(local);
    const SendPlan plan = build_send_plan(canonical, *need, local);
    stats.chunks_total = canonical.size();
    stats.chunks_skipped = canonical.size() - plan.size();
    if (high_water > plan.size()) return err(Err::kProtocol, "resume point past the plan");

    // --- stream the payload ---
    WANREP_TRY(send_plan_through_pipeline(link, writer, tree, local, plan, high_water, opt,
                                          stats));

    // --- commit ---
    {
      std::vector<uint8_t> p;
      put_varint(p, opt.generation);
      p.insert(p.end(), manifest_digest.begin(), manifest_digest.end());
      WANREP_TRY(writer.write(FrameType::kGenCommit, 0, ByteSpan(p.data(), p.size())));
      auto ack = reader.next();
      if (!ack.ok()) return ack.error();
      if (ack->type == FrameType::kError) return err(Err::kProtocol, "peer refused the commit");
      if (ack->type != FrameType::kCommitAck) return err(Err::kProtocol, "expected COMMIT_ACK");
      stats.round_trips++;
    }
    (void)writer.write(FrameType::kBye, 0, ByteSpan{});

    stats.wire_bytes_out = link.bytes_out();
    stats.wire_bytes_in = link.bytes_in();
    stats.frames_out = writer.frames_written();
    stats.frames_in += reader.frames_read();
    return stats;
  }

  // "Recovered cleanly from a dropped connection rather than restarting from the
  // beginning" (the second headline claim), as one callable thing. Reconnects and resumes, falling
  // back to a fresh negotiation when the target does not recognise the session -- which is
  // still not a restart, because the set difference excludes everything already stored.
  using LinkFactory = std::function<Result<std::shared_ptr<Link>>()>;

  static Result<JobStats> run_resilient(const LinkFactory& make_link, const std::string& tree,
                                        Options opt, int max_attempts = 6,
                                        int* attempts_used = nullptr) {
    // The tree is scanned ONCE and reused across attempts: re-walking it per retry would
    // be wasted I/O, and (worse) a tree that changed mid-retry would produce a different
    // manifest and invalidate the session.
    auto scanned = scan_tree(tree, opt.dataset, opt.generation);
    if (!scanned.ok()) return scanned.error();

    Error last = err(Err::kCancelled, "no attempt made");
    std::string session_id = opt.resume_session_id;
    JobStats best;
    uint64_t carried_out = 0, carried_in = 0;

    for (int attempt = 0; attempt < max_attempts; attempt++) {
      if (attempts_used != nullptr) *attempts_used = attempt + 1;
      auto link = make_link();
      if (!link.ok()) {
        last = link.error();
        continue;
      }
      Options a = opt;
      a.resume_session_id = session_id;
      auto r = run(**link, tree, a, &*scanned, &session_id);
      // Wire bytes accumulate across attempts -- reporting only the last attempt's would
      // understate the cost of a failure, which is exactly the number R2.4 is about.
      carried_out += (*link)->bytes_out();
      carried_in += (*link)->bytes_in();
      if (r.ok()) {
        best = *r;
        best.wire_bytes_out = carried_out;
        best.wire_bytes_in = carried_in;
        return best;
      }
      last = r.error();
      // kNotFound means the target does not know the session: retry FRESH, not resumed.
      if (last.code == Err::kNotFound) session_id.clear();
    }
    return last;
  }

 private:
  struct RawBatch {
    uint64_t seq = 0;
    std::vector<uint8_t> payload;
    size_t chunks = 0;
  };
  struct SentBatch {
    uint64_t seq = 0;
    std::vector<uint8_t> wire;
    uint32_t raw_len = 0;
    uint8_t flags = 0;
    size_t chunks = 0;
  };

  // Bounded push with yielding backpressure. Not lock-free, and not claimed to be: this
  // is the path that keeps memory constant (SPEC S10), and blocking here is the feature.
  template <class Q, class T>
  static bool push_blocking(Q& q, T&& v, const std::atomic<bool>& failed) {
    while (!q.try_push(std::move(v))) {
      if (failed.load(std::memory_order_acquire)) return false;
      std::this_thread::yield();
    }
    return true;
  }

  static Result<void> send_plan_through_pipeline(Link& link, FrameWriter& writer,
                                                 const std::string& tree, const Manifest& m,
                                                 const SendPlan& plan, uint64_t start,
                                                 const Options& opt, JobStats& stats) {
    (void)link;
    if (start >= plan.size()) return {};

    MpmcQueue<RawBatch> raw_q(64);
    MpmcQueue<SentBatch> out_q(64);
    std::atomic<bool> failed{false};
    std::atomic<size_t> produced{0};
    std::atomic<bool> produce_done{false};
    std::mutex err_mu;
    Error first_error;

    auto record = [&](const Error& e) {
      std::lock_guard<std::mutex> g(err_mu);
      if (!failed.exchange(true, std::memory_order_acq_rel)) first_error = e;
    };

    // Stage 1: read chunks from the source tree and pack them into batches.
    std::thread reader_thread([&] {
      SourceChunkReader src(tree, m);
      RawBatch batch;
      batch.seq = start;
      for (uint64_t i = start; i < plan.size() && !failed.load(std::memory_order_acquire); i++) {
        auto bytes = src.read(plan.chunks[i]);
        if (!bytes.ok()) {
          record(bytes.error());
          break;
        }
        put_varint(batch.payload, bytes->size());
        batch.payload.insert(batch.payload.end(), bytes->begin(), bytes->end());
        batch.chunks++;
        if (batch.payload.size() >= opt.batch_bytes) {
          const uint64_t next_seq = batch.seq + batch.chunks;
          produced.fetch_add(1, std::memory_order_release);
          if (!push_blocking(raw_q, std::move(batch), failed)) break;
          batch = RawBatch{};
          batch.seq = next_seq;
        }
      }
      if (batch.chunks > 0 && !failed.load(std::memory_order_acquire)) {
        produced.fetch_add(1, std::memory_order_release);
        (void)push_blocking(raw_q, std::move(batch), failed);
      }
      produce_done.store(true, std::memory_order_release);
    });

    // Stage 2: compress, on however many threads were asked for.
    std::vector<std::thread> compressors;
    const int nthreads = std::max(1, opt.compressor_threads);
    std::atomic<size_t> compressed{0};
    for (int t = 0; t < nthreads; t++) {
      compressors.emplace_back([&] {
        for (;;) {
          RawBatch in;
          if (!raw_q.try_pop(in)) {
            if (failed.load(std::memory_order_acquire)) return;
            if (produce_done.load(std::memory_order_acquire) &&
                compressed.load(std::memory_order_acquire) >=
                    produced.load(std::memory_order_acquire)) {
              return;
            }
            std::this_thread::yield();
            continue;
          }
          SentBatch out;
          out.seq = in.seq;
          out.chunks = in.chunks;
          out.raw_len = static_cast<uint32_t>(in.payload.size());
          const ByteSpan raw(in.payload.data(), in.payload.size());
          bool packed = false;
          if (opt.compress) {
            std::vector<uint8_t> tmp(lz::max_compressed_size(in.payload.size()));
            const size_t n = lz::compress(raw, tmp.data(), tmp.size());
            // SPEC S14: never expand. If it did not shrink, the raw bytes go on the wire.
            if (n > 0 && n < in.payload.size()) {
              tmp.resize(n);
              out.wire = std::move(tmp);
              out.flags = kFlagCompressed;
              packed = true;
            }
          }
          if (!packed) out.wire = std::move(in.payload);
          compressed.fetch_add(1, std::memory_order_release);
          if (!push_blocking(out_q, std::move(out), failed)) return;
        }
      });
    }

    // Stage 3: this thread owns the socket and does nothing else.
    size_t sent = 0;
    for (;;) {
      if (failed.load(std::memory_order_acquire)) break;
      if (produce_done.load(std::memory_order_acquire) &&
          sent >= produced.load(std::memory_order_acquire)) {
        break;
      }
      SentBatch b;
      if (!out_q.try_pop(b)) {
        std::this_thread::yield();
        continue;
      }
      auto w = writer.write(FrameType::kChunks, b.seq, ByteSpan(b.wire.data(), b.wire.size()),
                            b.flags, b.raw_len);
      if (!w.ok()) {
        record(w.error());
        break;
      }
      stats.chunks_sent += b.chunks;
      stats.payload_bytes_sent += b.raw_len;
      stats.compressed_bytes_sent += b.wire.size();
      sent++;
    }

    failed.store(true, std::memory_order_release);  // wake anyone still blocked on a full queue
    reader_thread.join();
    for (auto& t : compressors) t.join();
    // Drain, so a queue holding a batch cannot look like a successful send.
    RawBatch drop_raw;
    while (raw_q.try_pop(drop_raw)) {
    }
    SentBatch drop_out;
    while (out_q.try_pop(drop_out)) {
    }

    std::lock_guard<std::mutex> g(err_mu);
    if (first_error.code != Err::kOk) return first_error;
    return {};
  }
};

}  // namespace wanrep
