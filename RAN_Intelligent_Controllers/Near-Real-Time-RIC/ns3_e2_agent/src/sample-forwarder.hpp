// Turns one ns3-e2-ipc v1 sample into E2SM-KPM octets: one header, one cell
// message (format 1) and ceil(nUe / chunk) UE messages (format 2, at most
// E2_UES_PER_IND UEs each, the chunk halved while the encoded message exceeds
// E2_MAX_E2SM_BYTES). The same octets are sent under every subscription.
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

struct EncodedSample {
  int64_t seq = -1;
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
  // Validates a hello line against this agent's identity. False + reason on mismatch.
  bool accept_hello(const nlohmann::json &hello, HelloInfo &out, std::string &reason) const;
  // Encodes a sample. False if the sample could not be encoded at all.
  bool encode(const nlohmann::json &sample, const HelloInfo &hello, EncodedSample &out, std::string &err);

 private:
  bool encode_ue_chunks(const nlohmann::json &sample, unsigned long periodMs, EncodedSample &out, std::string &err);

  const Config &cfg_;
  const MetricMap &map_;
  Guami guami_;
  std::string senderName_;
};

}  // namespace agent

#endif
