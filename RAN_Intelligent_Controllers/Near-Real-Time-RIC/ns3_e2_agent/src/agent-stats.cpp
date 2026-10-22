// JSON stats line and process exit (see agent-stats.hpp).
#include "agent-stats.hpp"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sys/time.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include "agent-log.hpp"

namespace agent {

Stats &stats() {
  static Stats s;
  return s;
}

void print_stats_line(const Stats &s, const char *event, const std::string &reason) {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  nlohmann::ordered_json j;
  j["event"] = event;
  j["unixMs"] = (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
  j["nodeId"] = s.nodeId;
  j["state"] = s.state;
  j["subs"] = s.subs;
  j["setupFuncAccepted"] = s.setupFuncAccepted;
  j["lastSeq"] = s.lastSeq;
  j["samplesIn"] = s.samplesIn;
  j["samplesForwarded"] = s.samplesForwarded;
  j["dropped"] = {{"e2Down", s.droppedE2Down}, {"noSub", s.droppedNoSub}, {"sendBusy", s.droppedSendBusy},
                  {"encode", s.droppedEncode}, {"beforeHello", s.samplesBeforeHello}, {"badNode", s.samplesBadNode}};
  j["uesDropped"] = {{"oversize", s.uesDroppedOversize}, {"badImsi", s.uesDroppedBadImsi}};
  j["chunkSplits"] = s.chunkSplits;
  j["int32Overflow"] = s.conv.int32Overflow;
  j["typeMismatch"] = s.conv.typeMismatch;
  j["realInexact"] = s.conv.realInexact;
  j["indTx"] = s.indTx;
  j["indTxCell"] = s.indTxCell;
  j["indTxUe"] = s.indTxUe;
  j["ipc"] = {{"accepted", s.ipcAccepted}, {"rejectedSecond", s.ipcRejectedSecond},
              {"lineTooLong", s.ipcLineTooLong}, {"badJson", s.ipcBadJson}, {"helloAccepted", s.helloAccepted},
              {"helloRejected", s.helloRejected}, {"bye", s.byeRx}, {"unknownType", s.unknownType}};
  j["e2"] = {{"connectAttempts", s.connectAttempts}, {"connectFailures", s.connectFailures}, {"setups", s.setups},
             {"rxPdu", s.rxPdu}, {"rxPduUndecodable", s.rxPduUndecodable}, {"subsAdded", s.subsAdded},
             {"subsReplaced", s.subsReplaced}, {"subsDeleted", s.subsDeleted}, {"subsOtherFunc", s.subsOtherFunc},
             {"serviceQueries", s.serviceQueries}, {"errorIndications", s.errorIndications},
             {"otherPdus", s.otherPdus}, {"ctrlSendFailed", s.ctrlSendFailed}};
  j["rc"] = {{"rx", s.ctlRx}, {"rejFunc", s.ctlRejFunc}, {"rejDecode", s.ctlRejDecode},
             {"rejAction", s.ctlRejAction}, {"rejIpcDown", s.ctlRejIpcDown}, {"forwarded", s.ctlForwarded},
             {"applied", s.ctlApplied}, {"refused", s.ctlRefused}, {"failedOnBye", s.ctlFailedOnBye},
             {"ackTx", s.ctlAckTx}, {"failTx", s.ctlFailTx}, {"ackSuppressed", s.ctlAckSuppressed},
             {"ackUnknown", s.ctlAckUnknown}, {"ackBad", s.ctlAckBad}, {"pending", s.ctlPending}};
  j["stepsTx"] = s.stepsTx;
  if (!reason.empty()) j["reason"] = reason;
  fprintf(stdout, "%s\n", j.dump().c_str());
  fflush(stdout);
}

void agent_exit(int code, const std::string &reason) {
  ALOG_E("exit %d: %s", code, reason.c_str());
  print_stats_line(stats(), "exit", reason);
  fflush(stderr);
  _exit(code);
}

}  // namespace agent
