// Turns ns3-e2-ipc v1 samples into E2SM-KPM octets. Each sample's records are
// built once (SampleRecords). One report covers the samples of one reporting
// period (P / T consecutive samples, one per granularity period G = T): one
// header, one cell message (format 1, one measData item per sample) and
// ceil(nUe / chunk) UE messages (format 2, one measData item per sample, at most
// E2_UES_PER_IND UEs each, the chunk halved while the encoded message exceeds
// E2_MAX_E2SM_BYTES). At P = T a report is exactly one sample.
//
// UE IDs come from ns-3's `ueContext` lines (imsi -> MN LTE RNTI, MN cellId,
// MME UE S1AP ID), which a node sends before the sample of a seq whenever its
// UE set changed; each line replaces the node's whole set. A gNB agent reports
// en-gNB-UEID, the eNB agent eNB-UEID (kpm-encoder.hpp KpmUeId). A sample with
// a UE that has no context is not encoded (samplesNoUeContext): the IMSI is
// never encoded as a fallback KPM UE ID.
#ifndef NS3_E2_AGENT_SAMPLE_FORWARDER_HPP
#define NS3_E2_AGENT_SAMPLE_FORWARDER_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "agent-config.hpp"
#include "kpm-encoder.hpp"
#include "metric-map.hpp"

namespace agent {

struct EncodedReport {
  int64_t firstSeq = -1, lastSeq = -1;
  Bytes header;
  Bytes cellMsg;
  std::vector<Bytes> ueMsgs;
};

struct HelloInfo {
  int64_t periodNs = 0;
  int64_t simStartEpochMs = 0;
  std::string runId;
};

class SampleEncoder {
 public:
  SampleEncoder(const Config &cfg, const MetricMap &map);
  // Validates a hello line against this agent's identity and indication period
  // (periodNs must equal E2_INDICATION_PERIOD_MS). False + reason on mismatch.
  bool accept_hello(const nlohmann::json &hello, HelloInfo &out, std::string &reason) const;
  // Validates a ueContext line and makes its UEs the node's whole context set.
  // A line that is invalid (wrong node, a field outside its range, e.g. an LTE
  // RNTI above the m-eNB-UE-X2AP-ID range 0..4095, a repeated IMSI) clears the
  // set, so samples fail loudly instead of using stale IDs; false + reason.
  // Counts ipc.ueContext / ipc.ueContextRejected.
  bool accept_ue_context(const nlohmann::json &line, std::string &reason);
  // Forgets every UE context (a new ns-3 run or connection).
  void reset_ue_contexts();
  // Builds the records of one sample (conversion and UE-drop counters are
  // counted here, once per sample). False if the sample lacks seq or simTimeNs,
  // or if one of its UEs has no context (samplesNoUeContext + 1). The UE IDs of
  // a built sample's UEs are kept for the reports that cover it.
  bool build(const nlohmann::json &sample, SampleRecords &out, std::string &err);
  // Encodes one report over consecutive samples (oldest first). The header's
  // colletStartTime is the start of the first sample's collection window; the
  // UE messages cover the union of the samples' UEs, a UE absent from a sample
  // getting noValue records in that sample's measData item.
  bool encode(const std::vector<SampleRecords> &samples, const HelloInfo &hello, EncodedReport &out,
              std::string &err) const;

 private:
  bool encode_ue_chunks(const std::vector<SampleRecords> &samples, unsigned long granulMs, EncodedReport &out,
                        std::string &err) const;

  const Config &cfg_;
  const MetricMap &map_;
  std::string senderName_;
  std::map<uint64_t, KpmUeId> ueContexts_;  // the node's current set, by IMSI
  // UE ID of every IMSI as of the last built sample that had it. A report is
  // encoded right after its last sample is built, so this holds each of its
  // UEs' ID from the newest of its samples, also for a UE that has since left
  // the node's current set.
  std::map<uint64_t, KpmUeId> builtUeIds_;
};

}  // namespace agent

#endif
