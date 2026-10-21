// Agent configuration, read once from environment variables at start.
// The variable names and defaults are the ones fixed by the P3 design.
#ifndef NS3_E2_AGENT_CONFIG_HPP
#define NS3_E2_AGENT_CONFIG_HPP

#include <array>
#include <cstdint>
#include <string>

namespace agent {

struct Config {
  int nodeId = 0;                 // E2_NODE_ID (required): ns-3 cellId
  std::string kind;               // E2_NODE_KIND (required): "gnb" | "enb"
  std::string termAddr;           // E2_TERM_ADDR (required): e2term SCTP ClusterIP
  int termPort = 36422;           // E2_TERM_PORT
  std::string plmn = "00101";     // E2_PLMN: MCC (3 digits) + MNC (2 or 3 digits)
  std::array<uint8_t, 3> plmnBcd{};  // derived 3GPP TS 38.413 BCD form
  uint32_t gnbId = 0;             // E2_GNB_ID (default E2_NODE_ID), 29-bit value
  long ranFuncId = 2;             // E2_RAN_FUNC_ID
  std::string kpmOid = "1.3.6.1.4.1.53148.1.3.2.2";  // E2_KPM_OID
  int sctpSrcPort = 0;            // E2_SCTP_SRC_PORT (0 = ephemeral)
  int holdoffS = 8;               // E2_CONNECT_HOLDOFF_S
  int connectRetryS = 2;          // E2_CONNECT_RETRY_S
  int connectTimeoutS = 3;        // E2_CONNECT_TIMEOUT_S
  int setupTimeoutS = 10;         // E2_SETUP_TIMEOUT_S
  int ipcPort = 0;                // E2_IPC_PORT (default 38470 + E2_NODE_ID)
  std::string metricMapPath = "/etc/ns3-e2-agent/metric-map.v1.json";  // E2_METRIC_MAP
  int uesPerInd = 4;              // E2_UES_PER_IND
  int maxE2smBytes = 7000;        // E2_MAX_E2SM_BYTES
  int statsIntervalS = 5;         // E2_STATS_INTERVAL_S
};

// Revision advertised for the KPM RAN function (same as NIST's kpm_sim).
constexpr long kRanFunctionRevision = 2;

// Hard limit of NIST's indication generator (it copies the E2SM message into a
// fixed 8192-byte buffer); the agent never passes a larger message.
constexpr int kGeneratorMessageLimit = 8192;

// Reads the environment. On error prints the reason to stderr and returns false.
bool load_config_from_env(Config &cfg);

// "00101" -> {0x00, 0xF1, 0x10}. Returns false if the string is not 5 or 6 digits.
bool plmn_to_bcd(const std::string &plmn, std::array<uint8_t, 3> &out);

}  // namespace agent

#endif
