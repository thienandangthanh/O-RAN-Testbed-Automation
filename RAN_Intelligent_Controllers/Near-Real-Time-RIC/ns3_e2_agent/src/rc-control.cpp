// RC control path (see rc-control.hpp).
#include "rc-control.hpp"

#include <sys/time.h>

#include <cstring>

#include "agent-log.hpp"
#include "agent-stats.hpp"
#include "e2-node-identity.hpp"
#include "e2ap-builders.hpp"
#include "rc-codec.h"

extern "C" {
#include "CauseRICrequest.h"
}

namespace agent {

namespace {
int64_t unix_ms() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
}  // namespace

bool parse_target_nr_cgi(const uint8_t *o, size_t n, const std::array<uint8_t, 3> &plmn, TargetCell &out,
                         std::string &err) {
  uint8_t p[3];
  uint64_t nci = 0;
  char e[256] = {0};
  if (rcc_decode_nr_cgi_strict(o, n, p, &nci, e, sizeof e) != 0) {
    err = std::string("target ") + e;
    return false;
  }
  if (memcmp(p, plmn.data(), 3) != 0) {
    err = "target NR CGI: PLMN is not this node's";
    return false;
  }
  uint64_t gnbId = nci >> 4;
  if ((nci & 0xF) != kNrCellPart || gnbId < 1 || gnbId > 65535) {
    err = "target NR CGI: NR Cell Identity is not gNB ID (an ns-3 cellId) || cell part 1";
    return false;
  }
  out.gnbId = (uint32_t)gnbId;
  out.cellId = (uint16_t)gnbId;
  return true;
}

RcControlPath::RcControlPath(int nodeId, const std::array<uint8_t, 3> &plmn, SendE2 sendE2, SendIpc sendIpc)
    : nodeId_(nodeId), plmn_(plmn), sendE2_(std::move(sendE2)), sendIpc_(std::move(sendIpc)) {}

void RcControlPath::on_request(const InboundPdu &p, int64_t afterSeq, bool ipcUp) {
  stats().ctlRx++;
  PendingControl c;
  c.requestorId = p.requestorId;
  c.instanceId = p.instanceId;
  c.ranFuncId = p.ranFuncId;
  c.hasCallProcessId = p.hasCallProcessId;
  c.callProcessId = p.callProcessId;
  c.noAck = p.controlAckRequest == 0;  // RICcontrolAckRequest: 0 = noAck, 1 = ack
  if (p.ranFuncId != kRcRanFunctionId) {
    stats().ctlRejFunc++;
    answer_failure(c, CauseRICrequest_ran_function_id_invalid, "RAN function is not 3");
    return;
  }
  rcc_control rc;
  char err[256] = {0};
  if (rcc_decode_control(p.controlHeader.data(), p.controlHeader.size(), p.controlMessage.data(),
                         p.controlMessage.size(), &rc, err, sizeof err) != 0) {
    stats().ctlRejDecode++;
    answer_failure(c, CauseRICrequest_control_message_invalid, err);
    return;
  }
  if (rc.style != kRcStyleConnectedModeMobility || rc.action != kRcActionHandoverControl) {
    stats().ctlRejAction++;
    answer_failure(c, CauseRICrequest_action_not_supported, "style/action is not 3/1");
    return;
  }
  TargetCell t;
  std::string terr;
  if (!parse_target_nr_cgi(rc.targetOctets, rc.targetLen, plmn_, t, terr)) {
    stats().ctlRejDecode++;
    answer_failure(c, CauseRICrequest_control_message_invalid, terr.c_str());
    return;
  }
  if (!ipcUp) {
    stats().ctlRejIpcDown++;
    answer_failure(c, CauseRICrequest_control_failed_to_execute, "ns-3 not connected");
    return;
  }
  uint64_t ctlId = nextCtlId_++;
  // Recorded deviation P4: the AMF-UE-NGAP-ID carries the decimal IMSI.
  nlohmann::ordered_json j;
  j["type"] = "control";
  j["v"] = 1;
  j["nodeId"] = nodeId_;
  j["ctlId"] = ctlId;
  j["ric"] = {{"requestorId", c.requestorId}, {"instanceId", c.instanceId}, {"ranFuncId", c.ranFuncId}};
  j["style"] = rc.style;
  j["action"] = rc.action;
  j["imsi"] = rc.amfUeNgapId;
  j["targetCellId"] = t.cellId;
  j["afterSeq"] = afterSeq;
  j["diag"] = {{"targetGnbId", t.gnbId}, {"rxUnixMs", unix_ms()}};
  if (!sendIpc_(j.dump() + "\n")) {
    stats().ctlRejIpcDown++;
    answer_failure(c, CauseRICrequest_control_failed_to_execute, "IPC send failed");
    return;
  }
  pending_[ctlId] = c;
  stats().ctlForwarded++;
  stats().ctlPending = pending_.size();
  ALOG_I("control %ld/%ld -> ns-3 ctlId %llu: imsi %llu target cell %u (gNB %u) afterSeq %lld", c.requestorId,
         c.instanceId, (unsigned long long)ctlId, (unsigned long long)rc.amfUeNgapId, t.cellId, t.gnbId,
         (long long)afterSeq);
}

void RcControlPath::on_control_ack(const nlohmann::json &m) {
  if (!m.contains("ctlId") || !m["ctlId"].is_number_unsigned() || m.value("nodeId", -1) != nodeId_) {
    stats().ctlAckBad++;
    return;
  }
  auto it = pending_.find(m["ctlId"].get<uint64_t>());
  if (it == pending_.end()) {
    stats().ctlAckUnknown++;
    return;
  }
  PendingControl c = it->second;
  pending_.erase(it);
  stats().ctlPending = pending_.size();
  std::string outcome = m.value("outcome", ""), cause = m.value("cause", "");
  if (outcome == "applied") {
    stats().ctlApplied++;
    answer_ack(c);
  } else {
    stats().ctlRefused++;
    answer_failure(c, CauseRICrequest_control_failed_to_execute, ("ns-3 refused: " + cause).c_str());
  }
}

void RcControlPath::fail_all_pending(const char *why) {
  if (pending_.empty()) return;
  ALOG_W("%zu pending control(s) fail: %s", pending_.size(), why);
  std::map<uint64_t, PendingControl> all;
  all.swap(pending_);
  stats().ctlPending = 0;
  for (const auto &kv : all) {
    stats().ctlFailedOnBye++;
    answer_failure(kv.second, CauseRICrequest_control_failed_to_execute, why);
  }
}

void RcControlPath::answer_failure(const PendingControl &c, long cause, const char *why) {
  Bytes b;
  std::string err;
  if (!build_control_failure(c.requestorId, c.instanceId, c.ranFuncId, c.hasCallProcessId ? &c.callProcessId : nullptr,
                             cause, b, err)) {
    ALOG_E("RICcontrolFailure %ld/%ld: %s", c.requestorId, c.instanceId, err.c_str());
    return;
  }
  stats().ctlFailTx++;
  ALOG_I("control %ld/%ld fails (ricRequest cause %ld): %s", c.requestorId, c.instanceId, cause, why);
  sendE2_(b, "RICcontrolFailure");
}

void RcControlPath::answer_ack(const PendingControl &c) {
  if (c.noAck) {
    stats().ctlAckSuppressed++;  // E2AP 8.2.4.2: NoAck and success -> no message
    return;
  }
  uint8_t out[16];
  long n = rcc_encode_outcome_format1_empty(out, sizeof out);
  Bytes outcome(out, out + (n > 0 ? n : 0)), b;
  std::string err;
  if (n <= 0 || !build_control_ack(c.requestorId, c.instanceId, c.ranFuncId,
                                   c.hasCallProcessId ? &c.callProcessId : nullptr, outcome, b, err)) {
    ALOG_E("RICcontrolAcknowledge %ld/%ld: %s", c.requestorId, c.instanceId, n <= 0 ? "outcome encode" : err.c_str());
    answer_failure(c, CauseRICrequest_control_failed_to_execute, "RICcontrolAcknowledge could not be built");
    return;
  }
  stats().ctlAckTx++;
  sendE2_(b, "RICcontrolAcknowledge");
}

}  // namespace agent
