// Agent counters and the machine-readable JSON stats line (one per
// E2_STATS_INTERVAL_S on stdout, plus a final one at exit). Gates read these.
#ifndef NS3_E2_AGENT_STATS_HPP
#define NS3_E2_AGENT_STATS_HPP

#include <cstdint>
#include <string>

#include "metric-map.hpp"

namespace agent {

struct Stats {
  int nodeId = 0;
  std::string state = "HOLDOFF";
  size_t subs = 0;
  bool setupFuncAccepted = false;
  int64_t lastSeq = -1;
  // IPC side
  uint64_t ipcAccepted = 0, ipcRejectedSecond = 0, ipcLineTooLong = 0, ipcBadJson = 0;
  uint64_t helloAccepted = 0, helloRejected = 0, byeRx = 0, unknownType = 0;
  uint64_t samplesBeforeHello = 0, samplesBadNode = 0;
  // samples
  uint64_t samplesIn = 0, samplesForwarded = 0;
  uint64_t droppedE2Down = 0, droppedNoSub = 0, droppedSendBusy = 0, droppedEncode = 0;
  uint64_t uesDroppedOversize = 0, uesDroppedBadImsi = 0, chunkSplits = 0;
  ConvCounters conv;
  // E2 side
  uint64_t connectAttempts = 0, connectFailures = 0, setups = 0;
  uint64_t indTx = 0, indTxCell = 0, indTxUe = 0;
  uint64_t rxPdu = 0, rxPduUndecodable = 0, subsAdded = 0, subsReplaced = 0, subsDeleted = 0;
  uint64_t subsOtherFunc = 0, serviceQueries = 0, errorIndications = 0, otherPdus = 0, ctrlSendFailed = 0;
};

// Prints one JSON line to stdout and flushes. `event` is "stats" or "exit".
void print_stats_line(const Stats &s, const char *event, const std::string &reason = "");

// Prints the final stats line with `reason` and exits with `code`
// (2 = association lost, 3 = no/failed E2 setup, 1 = configuration error).
[[noreturn]] void agent_exit(int code, const std::string &reason);

// The process-wide counters (one agent per process).
Stats &stats();

}  // namespace agent

#endif
