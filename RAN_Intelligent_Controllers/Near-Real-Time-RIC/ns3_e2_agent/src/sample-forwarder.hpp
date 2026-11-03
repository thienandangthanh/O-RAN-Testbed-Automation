// Turns ns3-e2-ipc v1 samples into E2SM-KPM octets. Each sample's records are
// built once (SampleRecords). One report covers the samples of one reporting
// period (P / T consecutive samples, one per granularity period G = T): one
// header, one cell message (format 1, one measData item per sample) and
// ceil(nUe / chunk) UE messages (format 2, one measData item per sample, at most
// E2_UES_PER_IND UEs each, the chunk halved while the encoded message exceeds
// E2_MAX_E2SM_BYTES). At P = T a report is exactly one sample.
#ifndef NS3_E2_AGENT_SAMPLE_FORWARDER_HPP
#define NS3_E2_AGENT_SAMPLE_FORWARDER_HPP

#include <cstdint>
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
  // Builds the records of one sample (conversion and UE-drop counters are
  // counted here, once per sample). False if the sample lacks seq or simTimeNs.
  bool build(const nlohmann::json &sample, SampleRecords &out, std::string &err) const;
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
  Guami guami_;
  std::string senderName_;
};

}  // namespace agent

#endif
