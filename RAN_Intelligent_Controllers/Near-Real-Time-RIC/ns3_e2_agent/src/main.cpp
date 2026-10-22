// ns3-e2-agent: one out-of-process E2 agent per ns-O-RAN E2 node.
// Single thread, one poll() loop over: a 100 ms timerfd, the IPC listen
// socket, the IPC client socket and the SCTP association to e2term.
// NIST's libe2sim is used only for its PDU generators; run_loop, its
// callbacks, sctp_start_client, encode_and_send_sctp_data and the global
// client_fd are never used.
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <poll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include "agent-config.hpp"
#include "agent-log.hpp"
#include "agent-stats.hpp"
#include "e2-session.hpp"
#include "ipc-server.hpp"
#include "kpm-encoder.hpp"
#include "metric-map.hpp"
#include "rc-control.hpp"
#include "sample-forwarder.hpp"

using namespace agent;
using nlohmann::json;

namespace {

volatile sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

int64_t now_ms() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

struct IpcState {
  bool helloSeen = false;
  HelloInfo hello;
  bool lockstep = false;   // hello.pacing == "lockstep"
  bool readySent = false;  // step -1 sent on this connection
};

// Lock-step pacing (ns3-e2-ipc v1 minor 2): after every sample the agent tells
// ns-3 it is done with that step; seq -1 means READY with a subscription.
// Agents never block; ns-3's barrier waits for every node's step.
void send_step(const Config &cfg, IpcServer &ipc, int64_t seq) {
  if (seq == cfg.testWithholdStep && (cfg.testWithholdNode == 0 || cfg.testWithholdNode == cfg.nodeId)) {
    ALOG_W("test: withholding step %lld (E2_TEST_WITHHOLD_STEP)", (long long)seq);
    return;
  }
  nlohmann::ordered_json j;
  j["type"] = "step";
  j["v"] = 1;
  j["nodeId"] = cfg.nodeId;
  j["seq"] = seq;
  j["forwarded"] = stats().samplesForwarded;
  j["droppedNoSub"] = stats().droppedNoSub;
  j["controls"] = stats().ctlForwarded;
  ipc.send_line(j.dump() + "\n");
  stats().stepsTx++;
}

void forward_sample(const json &m, SampleEncoder &enc, E2Session &e2, IpcState &st) {
  if (!e2.ready()) {
    stats().droppedE2Down++;
    return;
  }
  if (e2.subscriptions() == 0) {
    stats().droppedNoSub++;
    return;
  }
  EncodedSample es;
  std::string err;
  if (!enc.encode(m, st.hello, es, err)) {
    stats().droppedEncode++;
    ALOG_E("sample seq %lld not encoded: %s", (long long)es.seq, err.c_str());
    return;
  }
  if (e2.forward(es)) stats().samplesForwarded++;
}

void handle_line(const std::string &line, const Config &cfg, SampleEncoder &enc, E2Session &e2, IpcServer &ipc,
                 IpcState &st, RcControlPath &rc) {
  json m = json::parse(line, nullptr, false);
  if (m.is_discarded() || !m.is_object()) {
    stats().ipcBadJson++;
    return;
  }
  std::string type = m.value("type", "");
  if (type == "hello") {
    std::string why;
    if (!enc.accept_hello(m, st.hello, why)) {
      stats().helloRejected++;
      ALOG_W("ipc: hello rejected: %s", why.c_str());
      ipc.close_client("hello rejected");
      st.helloSeen = false;
      return;
    }
    stats().helloAccepted++;
    st.helloSeen = true;
    st.lockstep = m.value("pacing", "free") == "lockstep";
    st.readySent = false;
    ALOG_I("ipc: hello accepted (runId %s, periodNs %lld, simStartEpochMs %lld)", st.hello.runId.c_str(),
           (long long)st.hello.periodNs, (long long)st.hello.simStartEpochMs);
  } else if (type == "sample") {
    if (!st.helloSeen) {
      stats().samplesBeforeHello++;
      return;
    }
    if (!m.contains("nodeId") || !m["nodeId"].is_number_integer() || m["nodeId"].get<int64_t>() != cfg.nodeId) {
      stats().samplesBadNode++;
      return;
    }
    stats().samplesIn++;
    if (m.contains("seq") && m["seq"].is_number_integer()) stats().lastSeq = m["seq"].get<int64_t>();
    forward_sample(m, enc, e2, st);
    if (st.lockstep) send_step(cfg, ipc, stats().lastSeq);
  } else if (type == "controlAck") {
    rc.on_control_ack(m);
  } else if (type == "bye") {
    stats().byeRx++;
    ALOG_I("ipc: bye %s", line.c_str());
    rc.fail_all_pending("ns-3 sent bye");
  } else {
    stats().unknownType++;  // unknown types are ignored (step is reserved for pacing)
  }
}

}  // namespace

int main() {
  unsetenv("RAN_FUNCTION_OP_TYPE");  // keeps NIST's service-update generator on "Modified"
  setvbuf(stderr, nullptr, _IOLBF, 0);
  Config cfg;
  if (!load_config_from_env(cfg)) return 1;
  stats().nodeId = cfg.nodeId;

  MetricMap map;
  std::string err;
  if (!load_metric_map(cfg.metricMapPath, cfg.kind, map, err)) agent_exit(1, "metric map: " + err);
  RanFunctionNames names;
  names.oid = cfg.kpmOid;
  names.description = "ns-O-RAN KPM map v1 " + map.sha256.substr(0, 8);
  Bytes def;
  if (!encode_ran_function_description(names, map.cell, map.ue, def, err)) agent_exit(1, "ranfunc: " + err);
  ALOG_I("node %d kind %s gNB-ID %u PLMN %s -> e2term %s:%d (src port %d); RAN function %ld OID %s", cfg.nodeId,
         cfg.kind.c_str(), cfg.gnbId, cfg.plmn.c_str(), cfg.termAddr.c_str(), cfg.termPort, cfg.sctpSrcPort,
         cfg.ranFuncId, cfg.kpmOid.c_str());
  ALOG_I("metric map %s sha256 %s: cell %zu, ue %zu items; definition %zu octets", cfg.metricMapPath.c_str(),
         map.sha256.c_str(), map.cell.size(), map.ue.size(), def.size());

  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_signal;
  sigaction(SIGTERM, &sa, nullptr);
  sigaction(SIGINT, &sa, nullptr);
  signal(SIGPIPE, SIG_IGN);

  IpcServer ipc;
  if (!ipc.listen(cfg.ipcPort, err)) agent_exit(1, err);
  ALOG_I("ipc: listening on tcp/%d", cfg.ipcPort);
  int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  struct itimerspec its = {{0, 100000000}, {0, 100000000}};
  timerfd_settime(tfd, 0, &its, nullptr);

  SampleEncoder enc(cfg, map);
  E2Session e2(cfg, def, now_ms());
  IpcState ist;
  RcControlPath rc(
      cfg.nodeId, [&e2](const Bytes &pdu, const char *what) { e2.send_ctrl(pdu, what); },
      [&ipc](const std::string &line) { return ipc.send_line(line); });
  e2.set_control_handler([&](const InboundPdu &p) {
    rc.on_request(p, stats().lastSeq, ipc.client_fd() >= 0 && ist.helloSeen);
  });
  int64_t nextStats = now_ms() + cfg.statsIntervalS * 1000LL;

  while (!g_stop) {
    struct pollfd fds[4];
    int n = 0, iTimer = n, iListen = -1, iClient = -1, iSctp = -1;
    fds[n++] = {tfd, POLLIN, 0};
    iListen = n;
    fds[n++] = {ipc.listen_fd(), POLLIN, 0};
    if (ipc.client_fd() >= 0)
      iClient = n, fds[n++] = {ipc.client_fd(), (short)(POLLIN | (ipc.want_write() ? POLLOUT : 0)), 0};
    short ev = 0;
    int sfd = e2.poll_fd(ev);
    if (sfd >= 0) iSctp = n, fds[n++] = {sfd, ev, 0};
    if (poll(fds, (nfds_t)n, 1000) < 0) {
      if (errno == EINTR) continue;
      agent_exit(1, std::string("poll: ") + strerror(errno));
    }
    int64_t now = now_ms();
    if (fds[iTimer].revents & POLLIN) {
      uint64_t ticks;
      if (read(tfd, &ticks, sizeof ticks) < 0) { /* nothing to do */ }
      e2.tick(now);
      if (now >= nextStats) {
        print_stats_line(stats(), "stats");
        nextStats = now + cfg.statsIntervalS * 1000LL;
      }
    }
    if (iSctp >= 0 && fds[iSctp].revents) e2.on_poll(fds[iSctp].revents, now);
    if (fds[iListen].revents & POLLIN && ipc.on_accept()) ist.helloSeen = false;
    if (iClient >= 0 && fds[iClient].revents) {
      if (fds[iClient].revents & POLLOUT) ipc.flush();
      std::vector<std::string> lines;
      if (ipc.client_fd() >= 0) ipc.on_readable(lines);
      for (const std::string &l : lines) handle_line(l, cfg, enc, e2, ipc, ist, rc);
      if (ipc.client_fd() < 0) {
        ist.helloSeen = false;
        rc.fail_all_pending("ns-3 IPC connection closed");
      }
    }
    if (ist.helloSeen && ist.lockstep && !ist.readySent && e2.ready() && e2.subscriptions() > 0) {
      send_step(cfg, ipc, -1);
      ist.readySent = true;
      ALOG_I("lock-step: READY with %zu subscription(s); step -1 sent", e2.subscriptions());
    }
  }
  e2.stop(2000);
  print_stats_line(stats(), "exit", "signal");
  return 0;
}
