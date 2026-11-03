// Agent configuration, read once from environment variables at start.
// The variable names and defaults are the ones fixed by the P3 design.
#ifndef NS3_E2_AGENT_CONFIG_HPP
#define NS3_E2_AGENT_CONFIG_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace agent {

struct Config {
  int nodeId = 0;                 // E2_NODE_ID (required): ns-3 cellId
  std::string kind;               // E2_NODE_KIND (required): "gnb" | "enb"
  std::string termAddr;           // E2_TERM_ADDR (required): e2term SCTP ClusterIP
  int termPort = 36422;           // E2_TERM_PORT
  std::string plmn = "00101";     // E2_PLMN: MCC (3 digits) + MNC (2 or 3 digits)
  std::array<uint8_t, 3> plmnBcd{};  // derived 3GPP TS 38.413 BCD form
  uint32_t gnbId = 0;             // E2_GNB_ID (default E2_NODE_ID): a gnb's 32-bit gNB ID (plan R-3: = ns-3 cellId);
                                  // an enb's macro eNB ID is E2_NODE_ID (20 bits)
  // E2_X2_PEERS (required): comma-separated ns-3 cellIds of the node's X2 neighbours, one X2 E2 node component
  // each (E2AP v03.00 §9.2.32): a gnb names its master eNB, an enb names every en-gNB.
  std::vector<uint32_t> x2Peers;
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
  // E2_INDICATION_PERIOD_MS: ns-3's indication period T (--indicationPeriodicity).
  // Known at start, so a RIC subscription that arrives before ns-3's hello (the
  // usual order: the gates start ns-3 after the subscription) is admitted or
  // refused against the same T; a hello with another periodNs is rejected.
  long indicationPeriodMs = 100;
  // E2_MAX_REPORT_RECORDS: largest K = P / T (measData items per RIC INDICATION)
  // the agent admits. Bounds the samples buffered per subscription and the size
  // of the (unchunked) cell Format 1 message: at the default the cell and UE
  // messages of the worst case stay within E2_MAX_E2SM_BYTES (tested).
  long maxReportRecords = 20;
  long testWithholdStep = -2;     // E2_TEST_WITHHOLD_STEP (test only): never send step <k>
  long testWithholdNode = 0;      // E2_TEST_WITHHOLD_NODE (test only): withhold only on this node id (0 = any)
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
