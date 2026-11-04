// Host unit test of the per-seq UE contexts of SampleEncoder (src/sample-forwarder.cpp).
//
// ns-3 sends a node's ueContext line before the sample of a seq whenever the
// node's UE set changed, and a line is the set from its seq on. A reporting
// period covers several samples, so the set can change inside one period: UE A
// leaves, UE C arrives and UE B gets another m-eNB-UE-X2AP-ID (a new LTE RNTI)
// at seq 12 of the period 10..13. Every sample must be encoded with the IDs of
// the line valid at its own seq:
//   ue-context-per-seq-mid-period-change  all K = 4 records of the period are
//       built and encoded (samplesNoUeContext unchanged); the report's UE
//       message lists (imsi, UE ID) pairs (1, X2AP 3), (2, X2AP 4), (2, X2AP 9),
//       (3, X2AP 5), each with records only in its own samples (noValue in the
//       others), octet for octet what encode_format2 gives for that assembly;
//   ue-context-per-seq-line-ahead          the same octets when the seq-12 line
//       arrives before the samples 10 and 11 are built;
//   ue-context-per-seq-prune               a line no later sample can use is
//       dropped, also for samples that are not built (no subscription);
//   ue-context-per-seq-before-first-line   a sample older than every kept line
//       is refused (samplesNoUeContext + 1).
// Prints PASS/FAIL <name>; exit 0 only if every check passes.
//
// usage: ue-context-per-seq-test <metric-map.json>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "../src/agent-config.hpp"
#include "../src/agent-stats.hpp"
#include "../src/kpm-encoder.hpp"
#include "../src/metric-map.hpp"
#include "../src/sample-forwarder.hpp"

using namespace agent;
using nlohmann::json;

namespace {

int failures = 0;

void verdict(const std::string &name, bool ok, const std::string &detail = "") {
  printf("%s %s%s%s\n", ok ? "PASS" : "FAIL", name.c_str(), detail.empty() ? "" : ": ", detail.c_str());
  if (!ok) failures++;
}

constexpr int kNode = 2;    // an en-gNB
constexpr int kMaster = 1;  // its master eNB (macro eNB ID)

json ctx(int64_t imsi, int64_t rnti) {
  return {{"imsi", imsi}, {"lteRnti", rnti}, {"mnCellId", kMaster}, {"mmeUeS1apId", imsi}};
}

json ue_context(int64_t seq, const json &ues) {
  return {{"type", "ueContext"}, {"v", 1}, {"nodeId", kNode}, {"seq", seq}, {"ues", ues}};
}

json sample(int64_t seq, const std::vector<int64_t> &imsis) {
  json ues = json::array();
  for (int64_t i : imsis) ues.push_back({{"imsi", i}});
  return {{"type", "sample"}, {"v", 1}, {"nodeId", kNode}, {"seq", seq}, {"simTimeNs", seq * 100000000},
          {"ipcDropped", 0}, {"cell", json::object()}, {"ues", ues}};
}

KpmUeId en_gnb(uint32_t rnti) {
  KpmUeId id;
  id.choice = KpmUeId::Choice::EnGnb;
  id.mEnbUeX2apId = rnti;
  id.macroEnbId = kMaster;
  return id;
}

// The period 10..13: lines at seq 10 {A=1: RNTI 3, B=2: RNTI 4} and seq 12 {B: RNTI 9, C=3: RNTI 5}.
const json kLine10 = ue_context(10, json::array({ctx(1, 3), ctx(2, 4)}));
const json kLine12 = ue_context(12, json::array({ctx(2, 9), ctx(3, 5)}));
const std::vector<json> kSamples = {sample(10, {1, 2}), sample(11, {1, 2}), sample(12, {2, 3}), sample(13, {2, 3})};

// The index of the UE-list row `kpm` in the metric map, or -1.
int ue_row(const MetricMap &map, const std::string &kpm) {
  for (size_t i = 0; i < map.ue.size(); i++)
    if (map.ue[i].kpm == kpm) return (int)i;
  return -1;
}

struct Built {
  bool ok = false;
  std::string err;
  std::vector<SampleRecords> recs;
};

// Feeds `lineAt` (line, before the sample with that index) and builds every sample of kSamples.
Built build_period(SampleEncoder &enc, const std::vector<std::pair<size_t, json>> &lineAt) {
  Built b;
  b.ok = true;
  for (size_t t = 0; t < kSamples.size() && b.ok; t++) {
    for (const auto &l : lineAt)
      if (l.first == t && !enc.accept_ue_context(l.second, b.err)) b.ok = false;
    SampleRecords r;
    if (b.ok && !enc.build(kSamples[t], r, b.err)) b.ok = false;
    b.recs.push_back(r);
  }
  return b;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <metric-map.json>\n", argv[0]);
    return 2;
  }
  Config cfg;
  cfg.nodeId = kNode;
  cfg.kind = "gnb";
  plmn_to_bcd(cfg.plmn, cfg.plmnBcd);
  MetricMap map;
  std::string err;
  if (!load_metric_map(argv[1], "gnb", map, err)) {
    fprintf(stderr, "metric map: %s\n", err.c_str());
    return 2;
  }
  const int seqRow = ue_row(map, "ns3.seq"), imsiRow = ue_row(map, "ns3.imsi");
  if (seqRow < 0 || imsiRow < 0) {
    fprintf(stderr, "metric map: no ns3.seq / ns3.imsi UE-list row\n");
    return 2;
  }
  HelloInfo hello;
  hello.periodNs = 100000000;
  hello.simStartEpochMs = 1792627200000LL;

  // The expected report: entries (imsi, UE ID) ascending IMSI, an IMSI's IDs in the order they appeared, and the
  // samples each entry has records in.
  const std::vector<std::pair<uint64_t, KpmUeId>> entries = {
      {1, en_gnb(3)}, {2, en_gnb(4)}, {2, en_gnb(9)}, {3, en_gnb(5)}};
  const std::vector<std::vector<size_t>> presentIn = {{0, 1}, {0, 1}, {2, 3}, {2, 3}};

  Bytes inOrder;
  {
    SampleEncoder enc(cfg, map);
    const uint64_t noCtx = stats().samplesNoUeContext;
    Built b = build_period(enc, {{0, kLine10}, {2, kLine12}});
    // each built record holds the IDs of the line valid at its seq, and its own seq and IMSI values
    bool idsOk = b.ok;
    for (size_t t = 0; idsOk && t < b.recs.size(); t++) {
      const SampleRecords &r = b.recs[t];
      idsOk = r.ues.size() == 2 && r.ueIds.size() == 2;
      for (size_t u = 0; idsOk && u < r.ues.size(); u++) {
        size_t e = 0;
        while (e < entries.size() && !(entries[e].first == r.ues[u].first && entries[e].second == r.ueIds[u])) e++;
        const bool inSample = e < entries.size() && (presentIn[e][0] == t || presentIn[e][1] == t);
        const MeasValue &seqV = r.ues[u].second[seqRow], &imsiV = r.ues[u].second[imsiRow];
        idsOk = inSample && seqV.kind == MeasValue::Integer && seqV.integer == (unsigned long)r.seq &&
                imsiV.kind == MeasValue::Integer && imsiV.integer == r.ues[u].first;
      }
    }
    EncodedReport rep;
    bool encOk = b.ok && enc.encode(b.recs, hello, rep, err) && rep.ueMsgs.size() == 1 && rep.firstSeq == 10 &&
                 rep.lastSeq == 13;
    // the oracle: encode_format2 of the expected assembly, the records of an entry taken from its own samples
    Bytes want;
    std::vector<std::vector<std::vector<MeasValue>>> periods(kSamples.size());
    std::vector<KpmUeId> ids;
    for (const auto &e : entries) ids.push_back(e.second);
    for (size_t t = 0; b.ok && t < kSamples.size(); t++)
      for (size_t e = 0; e < entries.size(); e++) {
        std::vector<MeasValue> v(map.ue.size());  // noValue records
        if (presentIn[e][0] == t || presentIn[e][1] == t)
          for (size_t u = 0; u < b.recs[t].ues.size(); u++)
            if (b.recs[t].ues[u].first == entries[e].first) v = b.recs[t].ues[u].second;
        periods[t].push_back(v);
      }
    bool wantOk = b.ok && encode_format2(periods, ids, map.ue, cfg.plmnBcd, true, 100, want, err);
    if (encOk) inOrder = rep.ueMsgs[0];
    verdict("ue-context-per-seq-mid-period-change",
            idsOk && encOk && wantOk && rep.ueMsgs[0] == want && stats().samplesNoUeContext == noCtx,
            std::to_string(b.recs.size()) + " records, " + (encOk ? std::to_string(rep.ueMsgs[0].size()) : "no") +
                " UE message octets" + (b.err.empty() && err.empty() ? "" : " (" + b.err + err + ")"));
  }
  {  // the seq-12 line arrives before the samples 10 and 11 are built: they still use the seq-10 line
    SampleEncoder enc(cfg, map);
    Built b = build_period(enc, {{0, kLine10}, {0, kLine12}});
    EncodedReport rep;
    bool ok = b.ok && enc.encode(b.recs, hello, rep, err) && rep.ueMsgs.size() == 1 && !inOrder.empty() &&
              rep.ueMsgs[0] == inOrder;
    verdict("ue-context-per-seq-line-ahead", ok, b.err);
  }
  {  // pruning: built samples and samples that are not built (prune_ue_contexts alone) drop unusable lines
    SampleEncoder enc(cfg, map);
    Built b = build_period(enc, {{0, kLine10}, {2, kLine12}});
    bool afterBuild = b.ok && enc.kept_ue_contexts() == 1;
    for (int64_t s = 20; s < 30; s++) {
      enc.accept_ue_context(ue_context(s, json::array({ctx(1, (int)s)})), err);
      enc.prune_ue_contexts(s);
    }
    bool unsubscribed = enc.kept_ue_contexts() == 1;
    SampleRecords r;
    bool stillValid = enc.build(sample(30, {1}), r, err) && r.ueIds.size() == 1 && r.ueIds[0] == en_gnb(29);
    verdict("ue-context-per-seq-prune", afterBuild && unsubscribed && stillValid,
            "kept " + std::to_string(enc.kept_ue_contexts()) + " line(s)");
  }
  {  // a sample older than the first kept line has no context
    SampleEncoder enc(cfg, map);
    enc.accept_ue_context(kLine12, err);
    const uint64_t noCtx = stats().samplesNoUeContext;
    SampleRecords r;
    std::string why;
    bool refused = !enc.build(sample(11, {2}), r, why) && stats().samplesNoUeContext == noCtx + 1;
    verdict("ue-context-per-seq-before-first-line", refused, why);
  }
  printf("ue-context-per-seq-test: %s\n", failures ? "FAIL" : "ok");
  return failures ? 1 : 0;
}
