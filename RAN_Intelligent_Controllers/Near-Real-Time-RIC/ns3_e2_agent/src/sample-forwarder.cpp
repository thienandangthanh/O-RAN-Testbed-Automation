// Sample -> E2SM-KPM octets (see sample-forwarder.hpp).
#include "sample-forwarder.hpp"

#include <algorithm>

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
  out.runId = h.value("runId", "");
  return true;
}

bool SampleEncoder::encode(const json &s, const HelloInfo &hello, EncodedSample &out, std::string &err) {
  out = EncodedSample{};
  int64_t simTimeNs = 0;
  get_i64(s, "seq", out.seq);
  if (!get_i64(s, "simTimeNs", simTimeNs)) {
    err = "sample without integer simTimeNs";
    return false;
  }
  // colletStartTime = start of the collection window, ms precision.
  int64_t periodMs = hello.periodNs / 1000000;
  int64_t simTimeMs = simTimeNs / 1000000;
  auto ts = ntp64_from_unix_ms(hello.simStartEpochMs + std::max<int64_t>(0, simTimeMs - periodMs));
  if (!encode_indication_header(ts, senderName_, kSenderType, kVendorName, out.header, err)) return false;

  std::vector<MeasValue> cell = build_records(map_.cell, s, nullptr, stats().conv);
  unsigned long granul = (unsigned long)std::max<int64_t>(1, periodMs);
  if (!encode_format1(cell, map_.cell, granul, out.cellMsg, err)) return false;
  return encode_ue_chunks(s, granul, out, err);
}

bool SampleEncoder::encode_ue_chunks(const json &s, unsigned long periodMs, EncodedSample &out, std::string &err) {
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

  size_t i = 0;
  while (i < ues.size()) {
    size_t chunk = std::min<size_t>((size_t)cfg_.uesPerInd, ues.size() - i);
    for (;;) {
      std::vector<std::vector<MeasValue>> perUe;
      std::vector<uint64_t> imsis;
      ConvCounters c;  // counted once, for the chunk that is kept
      for (size_t k = i; k < i + chunk; k++) {
        perUe.push_back(build_records(map_.ue, s, ues[k].second, c));
        imsis.push_back(ues[k].first);
      }
      Bytes msg;
      if (!encode_format2(perUe, imsis, map_.ue, guami_, true, periodMs, msg, err)) return false;
      if (msg.size() <= (size_t)cfg_.maxE2smBytes) {
        stats().conv.int32Overflow += c.int32Overflow;
        stats().conv.typeMismatch += c.typeMismatch;
        stats().conv.realInexact += c.realInexact;
        out.ueMsgs.push_back(std::move(msg));
        i += chunk;
        break;
      }
      if (chunk == 1) {
        ALOG_W("UE imsi %llu alone encodes to %zu > E2_MAX_E2SM_BYTES=%d octets; dropped",
               (unsigned long long)ues[i].first, msg.size(), cfg_.maxE2smBytes);
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
