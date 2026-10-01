// wanrep -- the command line (SPEC 4.2).
//
// Deliberately thin: every subcommand is a few lines over the library, because the
// library is what the tests exercise. A CLI that contains logic is a CLI whose logic is
// untested.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "wanrep/protocol.h"
#include "wanrep/tcp_link.h"
#include "wanrep/wan_link.h"

using namespace wanrep;

namespace {

struct Args {
  std::string store, listen, peer, tree, dataset = "default", out;
  uint64_t generation = 0;
  double rtt_ms = 0, bw_mbps = 0;
  bool deep = false;
  bool once = false;
};

int usage(int code) {
  std::fprintf(code == 0 ? stdout : stderr,
      "wanrep -- chunk-level replication over wide-area links\n\n"
      "  wanrep target serve       --store <dir> --listen <host:port> [--once]\n"
      "  wanrep target ls          --store <dir> [--dataset <name>]\n"
      "  wanrep target materialize --store <dir> --dataset <name> --gen <n> --out <dir>\n"
      "  wanrep target verify      --store <dir> [--deep]\n"
      "  wanrep source replicate   --tree <dir> --peer <host:port> --dataset <name>\n"
      "                            [--gen <n>] [--rtt <ms>] [--bw <Mbit/s>]\n\n"
      "Notes:\n"
      "  A store must live on a filesystem where flock actually excludes; wanrep refuses\n"
      "  to open one where it does not (see docs/CHALLENGES.md B2). Container-local\n"
      "  storage, not a bind mount.\n");
  return code;
}

bool parse(int argc, char** argv, int from, Args& a) {
  for (int i = from; i < argc; i++) {
    const std::string k = argv[i];
    auto next = [&](std::string& dst) {
      if (i + 1 >= argc) return false;
      dst = argv[++i];
      return true;
    };
    if (k == "--store" && next(a.store)) continue;
    if (k == "--listen" && next(a.listen)) continue;
    if (k == "--peer" && next(a.peer)) continue;
    if (k == "--tree" && next(a.tree)) continue;
    if (k == "--dataset" && next(a.dataset)) continue;
    if (k == "--out" && next(a.out)) continue;
    if (k == "--deep") { a.deep = true; continue; }
    if (k == "--once") { a.once = true; continue; }
    std::string v;
    if (k == "--gen" && next(v)) { a.generation = std::strtoull(v.c_str(), nullptr, 10); continue; }
    if (k == "--rtt" && next(v)) { a.rtt_ms = std::atof(v.c_str()); continue; }
    if (k == "--bw" && next(v)) { a.bw_mbps = std::atof(v.c_str()); continue; }
    std::fprintf(stderr, "unknown or incomplete option: %s\n", k.c_str());
    return false;
  }
  return true;
}

bool split_host_port(const std::string& s, std::string& host, uint16_t& port) {
  const size_t colon = s.rfind(':');
  if (colon == std::string::npos) return false;
  host = s.substr(0, colon);
  const long p = std::strtol(s.c_str() + colon + 1, nullptr, 10);
  if (p < 0 || p > 65535) return false;
  port = static_cast<uint16_t>(p);
  return true;
}

int fail(const Error& e) {
  std::fprintf(stderr, "error: %s\n", e.message().c_str());
  return 1;
}

int cmd_serve(const Args& a) {
  std::string host;
  uint16_t port = 0;
  if (a.store.empty() || !split_host_port(a.listen, host, port)) return usage(2);
  auto store = TargetStore::open(a.store);
  if (!store.ok()) return fail(store.error());
  auto sessions = SessionJournal::open(a.store);
  if (!sessions.ok()) return fail(sessions.error());
  auto listener = TcpLink::Listener::bind(host, port);
  if (!listener.ok()) return fail(listener.error());
  std::fprintf(stderr, "wanrep target listening on %s:%u (store %s)\n", host.c_str(),
               listener->port(), a.store.c_str());
  for (;;) {
    auto conn = listener->accept();
    if (!conn.ok()) return fail(conn.error());
    TargetServer server(**store, **sessions);
    auto r = server.serve(**conn);
    // A broken link is a normal outcome, not a reason to stop serving: the source
    // reconnects and resumes (SPEC 3.7).
    std::fprintf(stderr, "connection finished: %s\n",
                 r.ok() ? "ok" : r.error().message().c_str());
    (*conn)->close();
    if (a.once) break;
  }
  return 0;
}

int cmd_ls(const Args& a) {
  if (a.store.empty()) return usage(2);
  auto store = TargetStore::open(a.store);
  if (!store.ok()) return fail(store.error());
  for (const auto& ds : (*store)->generations().datasets()) {
    if (a.dataset != "default" && ds != a.dataset) continue;
    const auto gens = (*store)->generations().visible_generations(ds);
    std::printf("%s: %zu generation(s), prefix-consistent=%s\n", ds.c_str(), gens.size(),
                (*store)->generations().is_prefix_consistent(ds) ? "yes" : "NO");
    for (const uint64_t g : gens) {
      auto mb = (*store)->generations().manifest_bytes(ds, g);
      if (!mb.ok()) { std::printf("  gen %llu: UNREADABLE\n", (unsigned long long)g); continue; }
      auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
      if (!m.ok()) { std::printf("  gen %llu: UNDECODABLE\n", (unsigned long long)g); continue; }
      std::printf("  gen %llu: %zu files, %llu logical bytes, %zu chunk refs\n",
                  (unsigned long long)g, m->files.size(),
                  (unsigned long long)m->logical_bytes(), m->total_chunk_refs());
    }
  }
  std::printf("store: %zu chunks, %llu chunk bytes\n", (*store)->chunks().chunk_count(),
              (unsigned long long)(*store)->chunks().bytes_stored());
  return 0;
}

int cmd_materialize(const Args& a) {
  if (a.store.empty() || a.out.empty()) return usage(2);
  auto store = TargetStore::open(a.store);
  if (!store.ok()) return fail(store.error());
  auto mb = (*store)->generations().manifest_bytes(a.dataset, a.generation);
  if (!mb.ok()) return fail(mb.error());
  auto m = Manifest::decode(ByteSpan(mb->data(), mb->size()));
  if (!m.ok()) return fail(m.error());
  auto r = materialize(*m, (*store)->chunks(), a.out);
  if (!r.ok()) return fail(r.error());
  std::printf("materialized %s gen %llu -> %s (%zu files, %llu bytes)\n", a.dataset.c_str(),
              (unsigned long long)a.generation, a.out.c_str(), m->files.size(),
              (unsigned long long)m->logical_bytes());
  return 0;
}

int cmd_verify(const Args& a) {
  if (a.store.empty()) return usage(2);
  auto store = TargetStore::open(a.store);
  if (!store.ok()) return fail(store.error());
  auto v = (*store)->verify(a.deep);
  if (!v.ok()) return fail(v.error());
  std::printf("chunks=%zu generations=%zu problems=%zu\n", v->chunks, v->generations,
              v->problems);
  for (const auto& d : v->detail) std::printf("  %s\n", d.c_str());
  return v->problems == 0 ? 0 : 1;
}

int cmd_replicate(const Args& a) {
  std::string host;
  uint16_t port = 0;
  if (a.tree.empty() || !split_host_port(a.peer, host, port)) return usage(2);

  SourceJob::Options opt;
  opt.dataset = a.dataset;
  opt.generation = a.generation;

  // Reconnecting is the whole point of run_resilient: a dropped link resumes rather than
  // restarting (SPEC 3.7).
  SourceJob::LinkFactory factory = [&]() -> Result<std::shared_ptr<Link>> {
    auto tcp = TcpLink::connect(host, port);
    if (!tcp.ok()) return tcp.error();
    if (a.rtt_ms > 0 || a.bw_mbps > 0) {
      WanLink::Params p;
      p.rtt_ms = a.rtt_ms;
      p.bandwidth_mbps = a.bw_mbps;
      return std::static_pointer_cast<Link>(
          std::make_shared<WanLink>(std::static_pointer_cast<Link>(*tcp), p));
    }
    return std::static_pointer_cast<Link>(*tcp);
  };

  int attempts = 0;
  auto r = SourceJob::run_resilient(factory, a.tree, opt, 6, &attempts);
  if (!r.ok()) return fail(r.error());

  const double pct = 100.0 * static_cast<double>(r->wire_bytes_out) /
                     static_cast<double>(std::max<uint64_t>(1, r->logical_bytes));
  std::printf("replicated %s gen %llu in %d attempt(s)\n", a.dataset.c_str(),
              (unsigned long long)a.generation, attempts);
  std::printf("  logical      %llu bytes in %zu files\n",
              (unsigned long long)r->logical_bytes, r->files_total);
  std::printf("  on the wire  %llu bytes  (%.2f%% of logical, %.2fx reduction)\n",
              (unsigned long long)r->wire_bytes_out, pct,
              pct > 0 ? 100.0 / pct : 0.0);
  std::printf("  chunks       %zu sent, %zu already present, %zu total\n", r->chunks_sent,
              r->chunks_skipped, r->chunks_total);
  std::printf("  payload      %llu bytes -> %llu compressed\n",
              (unsigned long long)r->payload_bytes_sent,
              (unsigned long long)r->compressed_bytes_sent);
  std::printf("  manifest     %llu bytes\n", (unsigned long long)r->manifest_bytes_sent);
  std::printf("  round trips  %zu\n", r->round_trips);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) return usage(argc < 2 ? 1 : 0);
  const std::string group = argv[1];
  const std::string verb = argv[2];
  Args a;
  if (!parse(argc, argv, 3, a)) return 2;

  if (group == "target") {
    if (verb == "serve") return cmd_serve(a);
    if (verb == "ls") return cmd_ls(a);
    if (verb == "materialize") return cmd_materialize(a);
    if (verb == "verify") return cmd_verify(a);
  } else if (group == "source") {
    if (verb == "replicate") return cmd_replicate(a);
  }
  return usage(2);
}
