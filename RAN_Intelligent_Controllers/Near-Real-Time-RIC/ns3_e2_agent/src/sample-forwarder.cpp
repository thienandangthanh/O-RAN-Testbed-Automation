// Samples -> E2SM-KPM octets (see sample-forwarder.hpp).
#include "sample-forwarder.hpp"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>

#include "agent-log.hpp"
#include "agent-stats.hpp"

namespace agent {

using nlohmann::json;

namespace {

// An IMSI has at most 15 digits (3GPP TS 23.003). For the UE ID it is only the
// key that maps a sample UE to its ueContext; it is never encoded as the KPM UE
// ID (the metric map's UE-list rows may still report it as a measurement).
constexpr int64_t kMaxImsi = 999999999999999LL;
constexpr int64_t kMaxMmeUeS1apId = 4294967295LL;  // MME-UE-S1AP-ID ::= INTEGER (0..2^32-1)

bool get_i64(const json &j, const char *key, int64_t &out) {
  auto it = j.find(key);
  if (it == j.end() || !it->is_number_integer()) return false;
  if (it->is_number_unsigned() && it->get<uint64_t>() > (uint64_t)INT64_MAX) return false;
  out = it->get<int64_t>();
  return true;
}

// An integer field within lo..hi; otherwise false + reason naming it.
bool get_ranged(const json &j, const char *key, int64_t lo, int64_t hi, int64_t &out, std::string &reason) {
  if (!get_i64(j, key, out)) {
    reason = std::string(key) + " missing or not an integer";
    return false;
  }
  if (out < lo || out > hi) {
    reason = std::string(key) + " " + std::to_string(out) + " outside " + std::to_string(lo) + ".." +
             std::to_string(hi);
    return false;
  }
  return true;
}

// ueContext line -> imsi -> UE ID of a node of `kind` (see accept_ue_context).
bool parse_ue_context(const json &l, const Config &cfg, int64_t &seq, std::map<uint64_t, KpmUeId> &out,
                      std::string &reason) {
  int64_t v = 0, node = 0;
  if (!get_i64(l, "v", v) || v != 1) {
    reason = "v is not 1";
    return false;
  }
  if (!get_i64(l, "nodeId", node) || node != cfg.nodeId) {
    reason = "nodeId does not match E2_NODE_ID=" + std::to_string(cfg.nodeId);
    return false;
  }
  if (!get_ranged(l, "seq", 0, INT64_MAX, seq, reason)) return false;
  auto it = l.find("ues");
  if (it == l.end() || !it->is_array()) {
    reason = "ues missing or not an array";
    return false;
  }
  const bool enb = cfg.kind == "enb";
  for (const json &u : *it) {
    if (!u.is_object()) {
      reason = "ues entry is not an object";
      return false;
    }
    int64_t imsi = 0, rnti = 0, cell = 0, s1ap = 0;
    std::string why;
    if (!get_ranged(u, "imsi", 0, kMaxImsi, imsi, why) ||
        !get_ranged(u, "lteRnti", 0, kMaxEnbUeX2apId, rnti, why) ||
        !get_ranged(u, "mnCellId", 0, kMaxMacroEnbId, cell, why) ||
        !get_ranged(u, "mmeUeS1apId", 0, kMaxMmeUeS1apId, s1ap, why)) {
      reason = "UE entry " + std::to_string(out.size()) + ": " + why;
      return false;
    }
    KpmUeId id;
    id.choice = enb ? KpmUeId::Choice::Enb : KpmUeId::Choice::EnGnb;
    id.mEnbUeX2apId = (uint32_t)rnti;
    id.macroEnbId = (uint32_t)cell;
    id.mmeUeS1apId = (uint32_t)s1ap;
    if (!out.emplace((uint64_t)imsi, id).second) {
      reason = "imsi " + std::to_string(imsi) + " repeated";
      return false;
    }
  }
  return true;
}

}  // namespace

SampleEncoder::SampleEncoder(const Config &cfg, const MetricMap &map)
    : cfg_(cfg), map_(map), senderName_("ns3-cell-" + std::to_string(cfg.nodeId)) {}

bool SampleEncoder::accept_ue_context(const json &line, std::string &reason) {
  std::map<uint64_t, KpmUeId> next;
  int64_t seq = 0;
  if (!parse_ue_context(line, cfg_, seq, next, reason)) {
    contextsBySeq_.clear();
    stats().ueContextRejected++;
    return false;
  }
  contextsBySeq_[seq] = std::move(next);
  stats().ueContextRx++;
  return true;
}

void SampleEncoder::reset_ue_contexts() { contextsBySeq_.clear(); }

void SampleEncoder::prune_ue_contexts(int64_t seq) {
  auto valid = contextsBySeq_.upper_bound(seq);
  if (valid != contextsBySeq_.begin()) contextsBySeq_.erase(contextsBySeq_.begin(), std::prev(valid));
}

bool SampleEncoder::accept_hello(const json &h, HelloInfo &out, std::string &reason) const {
  int64_t v = 0, node = 0;
  if (h.value("schema", "") != "ns3-e2-ipc" || !get_i64(h, "v", v) || v != 1) {
    reason = "schema/v is not ns3-e2-ipc v1";
    return false;
  }
  if (!get_i64(h, "nodeId", node) || node != cfg_.nodeId) {
    reason = "nodeId does not match E2_NODE_ID=" + std::to_string(cfg_.nodeId);
    return false;
  }
  if (h.value("kind", "") != cfg_.kind) {
    reason = "kind does not match E2_NODE_KIND=" + cfg_.kind;
    return false;
  }
  if (!get_i64(h, "periodNs", out.periodNs) || out.periodNs <= 0 ||
      !get_i64(h, "simStartEpochMs", out.simStartEpochMs)) {
    reason = "periodNs/simStartEpochMs missing or invalid";
    return false;
  }
  if (out.periodNs != cfg_.indicationPeriodMs * 1000000) {
    reason = "periodNs " + std::to_string(out.periodNs) + " does not match E2_INDICATION_PERIOD_MS=" +
             std::to_string(cfg_.indicationPeriodMs);
    return false;
  }
  out.runId = h.value("runId", "");
  return true;
}

bool SampleEncoder::build(const json &s, SampleRecords &out, std::string &err) {
  out = SampleRecords{};
  if (!get_i64(s, "seq", out.seq) || !get_i64(s, "simTimeNs", out.simTimeNs)) {
    err = "sample without integer seq/simTimeNs";
    return false;
  }
  out.cell = build_records(map_.cell, s, nullptr, stats().conv);
  auto it = s.find("ues");
  if (it == s.end() || !it->is_array()) return true;  // no UE list: cell report only
  std::vector<std::pair<uint64_t, const json *>> ues;
  for (const json &u : *it) {
    auto im = u.find("imsi");
    if (im == u.end() || !im->is_number_integer() || im->get<int64_t>() < 0 || im->get<int64_t>() > kMaxImsi) {
      stats().uesDroppedBadImsi++;
      continue;
    }
    ues.emplace_back(im->get<uint64_t>(), &u);
  }
  std::stable_sort(ues.begin(), ues.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
  for (const auto &u : ues) {
    // A repeated IMSI in one sample: only its first entry is the UE's report and
    // the others are dropped (uesDropped.duplicateImsi). A report holds one
    // record set per UE and period, and a measData item cannot carry the same UE
    // twice (KPM v03.00 matchingUEidList); earlier, P = T reports encoded each
    // entry. No ns-3 trace seen so far repeats an IMSI.
    if (!out.ues.empty() && out.ues.back().first == u.first) {
      stats().uesDroppedDuplicateImsi++;
      continue;
    }
    out.ues.emplace_back(u.first, build_records(map_.ue, s, u.second, stats().conv));
  }
  prune_ue_contexts(out.seq);  // later samples have higher seqs
  if (out.ues.empty()) return true;  // no UE: no context needed
  // the line valid at this seq: the latest one whose seq is not above it (after the prune, the first one)
  auto valid = contextsBySeq_.upper_bound(out.seq);
  const std::map<uint64_t, KpmUeId> *ctx = valid == contextsBySeq_.begin() ? nullptr : &std::prev(valid)->second;
  std::string missing;
  for (const auto &u : out.ues)
    if (!ctx || !ctx->count(u.first)) missing += (missing.empty() ? "" : ",") + std::to_string(u.first);
  if (!missing.empty()) {
    stats().samplesNoUeContext++;
    err = "seq " + std::to_string(out.seq) + ": UE imsi " + missing + " without ueContext valid at that seq";
    return false;
  }
  for (const auto &u : out.ues) out.ueIds.push_back(ctx->at(u.first));
  return true;
}

bool SampleEncoder::encode(const std::vector<SampleRecords> &samples, const HelloInfo &hello, EncodedReport &out,
                           std::string &err) const {
  out = EncodedReport{};
  if (samples.empty()) {
    err = "report without samples";
    return false;
  }
  out.firstSeq = samples.front().seq;
  out.lastSeq = samples.back().seq;
  // colletStartTime = start of the first sample's collection window, ms precision.
  int64_t periodMs = hello.periodNs / 1000000;
  int64_t simTimeMs = samples.front().simTimeNs / 1000000;
  auto ts = ntp64_from_unix_ms(hello.simStartEpochMs + std::max<int64_t>(0, simTimeMs - periodMs));
  if (!encode_indication_header(ts, senderName_, kSenderType, kVendorName, out.header, err)) return false;

  std::vector<std::vector<MeasValue>> cell;
  for (const SampleRecords &r : samples) cell.push_back(r.cell);
  unsigned long granul = (unsigned long)std::max<int64_t>(1, periodMs);
  if (!encode_format1(cell, map_.cell, granul, out.cellMsg, err)) return false;
  return encode_ue_chunks(samples, granul, out, err);
}

bool SampleEncoder::encode_ue_chunks(const std::vector<SampleRecords> &samples, unsigned long granulMs,
                                     EncodedReport &out, std::string &err) const {
  // UE list of the report: the union of the samples' (IMSI, UE ID) pairs, ascending IMSI, an IMSI's IDs in the
  // order they appeared; bySample[t][e] = the records of entry e in sample t.
  std::vector<std::pair<uint64_t, KpmUeId>> entries;
  std::vector<std::map<size_t, const std::vector<MeasValue> *>> bySample(samples.size());
  for (size_t t = 0; t < samples.size(); t++) {
    const SampleRecords &r = samples[t];
    if (r.ueIds.size() != r.ues.size()) {
      err = "seq " + std::to_string(r.seq) + ": UE records without their UE IDs (not built by this encoder)";
      return false;
    }
    for (size_t u = 0; u < r.ues.size(); u++) {
      std::pair<uint64_t, KpmUeId> key{r.ues[u].first, r.ueIds[u]};
      auto e = std::find(entries.begin(), entries.end(), key);
      if (e == entries.end()) e = entries.insert(entries.end(), key);
      bySample[t][(size_t)(e - entries.begin())] = &r.ues[u].second;
    }
  }
  std::vector<size_t> order(entries.size());
  for (size_t e = 0; e < order.size(); e++) order[e] = e;
  std::stable_sort(order.begin(), order.end(),
                   [&](size_t a, size_t b) { return entries[a].first < entries[b].first; });
  const std::vector<MeasValue> absent(map_.ue.size());  // noValue records

  size_t i = 0;
  while (i < order.size()) {
    size_t chunk = std::min<size_t>((size_t)cfg_.uesPerInd, order.size() - i);
    for (;;) {
      std::vector<std::vector<std::vector<MeasValue>>> periods(samples.size());
      std::vector<KpmUeId> ids;
      for (size_t k = i; k < i + chunk; k++) ids.push_back(entries[order[k]].second);
      for (size_t t = 0; t < samples.size(); t++)
        for (size_t k = i; k < i + chunk; k++) {
          auto f = bySample[t].find(order[k]);
          periods[t].push_back(f == bySample[t].end() ? absent : *f->second);
        }
      Bytes msg;
      if (!encode_format2(periods, ids, map_.ue, cfg_.plmnBcd, true, granulMs, msg, err)) return false;
      if (msg.size() <= (size_t)cfg_.maxE2smBytes) {
        out.ueMsgs.push_back(std::move(msg));
        i += chunk;
        break;
      }
      if (chunk == 1) {
        ALOG_W("UE imsi %llu alone encodes to %zu > E2_MAX_E2SM_BYTES=%d octets; dropped",
               (unsigned long long)entries[order[i]].first, msg.size(), cfg_.maxE2smBytes);
        stats().uesDroppedOversize++;
        i += 1;
        break;
      }
      chunk = (chunk + 1) / 2;
      stats().chunkSplits++;
    }
  }
  return true;
}

}  // namespace agent
