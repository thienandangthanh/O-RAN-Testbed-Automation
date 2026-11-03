// Samples -> E2SM-KPM octets (see sample-forwarder.hpp).
#include "sample-forwarder.hpp"

#include <algorithm>
#include <map>

#include "agent-log.hpp"
#include "agent-stats.hpp"

namespace agent {

using nlohmann::json;

namespace {

constexpr uint64_t kMaxAmfUeNgapId = (1ULL << 40) - 1;  // AMF-UE-NGAP-ID ::= INTEGER (0..2^40-1)

bool get_i64(const json &j, const char *key, int64_t &out) {
  auto it = j.find(key);
  if (it == j.end() || !it->is_number_integer()) return false;
  out = it->get<int64_t>();
  return true;
}

}  // namespace

SampleEncoder::SampleEncoder(const Config &cfg, const MetricMap &map)
    : cfg_(cfg), map_(map), senderName_("ns3-cell-" + std::to_string(cfg.nodeId)) {
  guami_.plmn = cfg.plmnBcd;
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

bool SampleEncoder::build(const json &s, SampleRecords &out, std::string &err) const {
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
    if (im == u.end() || !im->is_number_integer() || im->get<int64_t>() < 0 ||
        im->get<uint64_t>() > kMaxAmfUeNgapId) {
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
  // UE list of the report: the union of the samples' UEs, ascending IMSI.
  std::vector<uint64_t> ues;
  for (const SampleRecords &r : samples)
    for (const auto &u : r.ues) ues.push_back(u.first);
  std::sort(ues.begin(), ues.end());
  ues.erase(std::unique(ues.begin(), ues.end()), ues.end());
  std::vector<std::map<uint64_t, const std::vector<MeasValue> *>> bySample(samples.size());
  for (size_t t = 0; t < samples.size(); t++)
    for (const auto &u : samples[t].ues) bySample[t][u.first] = &u.second;
  const std::vector<MeasValue> absent(map_.ue.size());  // noValue records

  size_t i = 0;
  while (i < ues.size()) {
    size_t chunk = std::min<size_t>((size_t)cfg_.uesPerInd, ues.size() - i);
    for (;;) {
      std::vector<std::vector<std::vector<MeasValue>>> periods(samples.size());
      std::vector<uint64_t> imsis(ues.begin() + i, ues.begin() + i + chunk);
      for (size_t t = 0; t < samples.size(); t++)
        for (uint64_t imsi : imsis) {
          auto f = bySample[t].find(imsi);
          periods[t].push_back(f == bySample[t].end() ? absent : *f->second);
        }
      Bytes msg;
      if (!encode_format2(periods, imsis, map_.ue, guami_, true, granulMs, msg, err)) return false;
      if (msg.size() <= (size_t)cfg_.maxE2smBytes) {
        out.ueMsgs.push_back(std::move(msg));
        i += chunk;
        break;
      }
      if (chunk == 1) {
        ALOG_W("UE imsi %llu alone encodes to %zu > E2_MAX_E2SM_BYTES=%d octets; dropped",
               (unsigned long long)ues[i], msg.size(), cfg_.maxE2smBytes);
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
