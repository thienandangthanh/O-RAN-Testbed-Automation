// Environment parsing for the agent configuration (see agent-config.hpp).
#include "agent-config.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>

namespace agent {

namespace {

// Parses an optional integer variable within [lo, hi]; keeps `out` when unset.
bool env_int(const char *name, long lo, long hi, long &out) {
  const char *v = getenv(name);
  if (!v || !*v) return true;
  char *end = nullptr;
  errno = 0;
  long x = strtol(v, &end, 10);
  if (errno || *end || x < lo || x > hi) {
    fprintf(stderr, "config: %s=%s is not an integer in [%ld, %ld]\n", name, v, lo, hi);
    return false;
  }
  out = x;
  return true;
}

bool env_int(const char *name, long lo, long hi, int &out) {
  long x = out;
  if (!env_int(name, lo, hi, x)) return false;
  out = (int)x;
  return true;
}

void env_str(const char *name, std::string &out) {
  const char *v = getenv(name);
  if (v && *v) out = v;
}

// "1" or "2,3,4": decimal cellIds in [1, 65535], no duplicates.
bool parse_x2_peers(const std::string &v, std::vector<uint32_t> &out) {
  out.clear();
  size_t i = 0;
  while (i <= v.size()) {
    size_t j = v.find(',', i);
    if (j == std::string::npos) j = v.size();
    std::string t = v.substr(i, j - i);
    if (t.empty() || t.size() > 5 || t.find_first_not_of("0123456789") != std::string::npos) return false;
    long x = strtol(t.c_str(), nullptr, 10);
    if (x < 1 || x > 65535) return false;
    for (uint32_t p : out)
      if (p == (uint32_t)x) return false;
    out.push_back((uint32_t)x);
    i = j + 1;
  }
  return !out.empty();
}

}  // namespace

bool plmn_to_bcd(const std::string &p, std::array<uint8_t, 3> &out) {
  if (p.size() != 5 && p.size() != 6) return false;
  for (char c : p)
    if (c < '0' || c > '9') return false;
  auto d = [&](size_t i) { return (uint8_t)(p[i] - '0'); };
  uint8_t mnc3 = p.size() == 6 ? d(5) : 0x0F;  // filler F for a 2-digit MNC
  out[0] = (uint8_t)(d(1) << 4 | d(0));         // MCC2 MCC1
  out[1] = (uint8_t)(mnc3 << 4 | d(2));         // MNC3 MCC3
  out[2] = (uint8_t)(d(4) << 4 | d(3));         // MNC2 MNC1
  return true;
}

bool load_config_from_env(Config &cfg) {
  bool ok = true;
  long node = -1;
  if (!env_int("E2_NODE_ID", 1, 65535, node) || node < 0) {
    fprintf(stderr, "config: E2_NODE_ID is required (1..65535)\n");
    return false;
  }
  cfg.nodeId = (int)node;
  env_str("E2_NODE_KIND", cfg.kind);
  if (cfg.kind != "gnb" && cfg.kind != "enb") {
    fprintf(stderr, "config: E2_NODE_KIND must be gnb or enb\n");
    ok = false;
  }
  env_str("E2_TERM_ADDR", cfg.termAddr);
  if (cfg.termAddr.empty()) {
    fprintf(stderr, "config: E2_TERM_ADDR is required\n");
    ok = false;
  }
  env_str("E2_PLMN", cfg.plmn);
  if (!plmn_to_bcd(cfg.plmn, cfg.plmnBcd)) {
    fprintf(stderr, "config: E2_PLMN must be 5 or 6 digits (MCC+MNC)\n");
    ok = false;
  }
  long gnb = cfg.nodeId;
  ok = env_int("E2_GNB_ID", 0, (1L << 32) - 1, gnb) && ok;
  cfg.gnbId = (uint32_t)gnb;
  std::string peers;
  env_str("E2_X2_PEERS", peers);
  if (!parse_x2_peers(peers, cfg.x2Peers)) {
    fprintf(stderr, "config: E2_X2_PEERS is required: comma-separated cellIds in [1, 65535], no duplicates\n");
    ok = false;
  }
  ok = env_int("E2_TERM_PORT", 1, 65535, cfg.termPort) && ok;
  ok = env_int("E2_RAN_FUNC_ID", 0, 4095, cfg.ranFuncId) && ok;
  env_str("E2_KPM_OID", cfg.kpmOid);
  ok = env_int("E2_SCTP_SRC_PORT", 0, 65535, cfg.sctpSrcPort) && ok;
  ok = env_int("E2_CONNECT_HOLDOFF_S", 0, 3600, cfg.holdoffS) && ok;
  ok = env_int("E2_CONNECT_RETRY_S", 1, 3600, cfg.connectRetryS) && ok;
  ok = env_int("E2_CONNECT_TIMEOUT_S", 1, 3600, cfg.connectTimeoutS) && ok;
  ok = env_int("E2_SETUP_TIMEOUT_S", 1, 3600, cfg.setupTimeoutS) && ok;
  cfg.ipcPort = 38470 + cfg.nodeId;
  ok = env_int("E2_IPC_PORT", 1, 65535, cfg.ipcPort) && ok;
  env_str("E2_METRIC_MAP", cfg.metricMapPath);
  ok = env_int("E2_UES_PER_IND", 1, 1024, cfg.uesPerInd) && ok;
  ok = env_int("E2_MAX_E2SM_BYTES", 256, kGeneratorMessageLimit, cfg.maxE2smBytes) && ok;
  ok = env_int("E2_STATS_INTERVAL_S", 1, 3600, cfg.statsIntervalS) && ok;
  ok = env_int("E2_INDICATION_PERIOD_MS", 1, 3600000, cfg.indicationPeriodMs) && ok;
  ok = env_int("E2_MAX_REPORT_RECORDS", 1, 65535, cfg.maxReportRecords) && ok;  // KPM maxnoofMeasurementRecord
  ok = env_int("E2_TEST_WITHHOLD_STEP", -1, 1L << 40, cfg.testWithholdStep) && ok;
  ok = env_int("E2_TEST_WITHHOLD_NODE", 0, 65535, cfg.testWithholdNode) && ok;
  return ok;
}

}  // namespace agent
