// E2 session state machine (see e2-session.hpp).
#include "e2-session.hpp"

#include <algorithm>
#include <poll.h>

#include "agent-log.hpp"
#include "agent-stats.hpp"
#include "e2ap-builders.hpp"
#include "kpm-subscription-admission.hpp"

namespace agent {

namespace {
const char *state_name(E2Session::State s) {
  static const char *n[] = {"HOLDOFF", "CONNECTING", "SETUP_SENT", "READY"};
  return n[(int)s];
}
}  // namespace

E2Session::E2Session(const Config &cfg, const Bytes &ranFuncDef, int64_t nowMs) : cfg_(cfg), ranFuncDef_(ranFuncDef) {
  deadlineMs_ = nowMs + cfg.holdoffS * 1000LL;
  set_state(State::Holdoff);
  ALOG_I("HOLDOFF %d s before the first connect", cfg.holdoffS);
}

void E2Session::set_state(State s) {
  state_ = s;
  stats().state = state_name(s);
  stats().subs = subs_.size();
}

void E2Session::tick(int64_t nowMs) {
  if (nowMs < deadlineMs_) return;
  switch (state_) {
    case State::Holdoff: start_attempt(nowMs); break;
    case State::Connecting:
      if (waitingRetry_) start_attempt(nowMs);
      else attempt_failed("connect timeout", nowMs);
      break;
    case State::SetupSent: agent_exit(3, "no E2SetupResponse within E2_SETUP_TIMEOUT_S");
    case State::Ready: break;
  }
}

void E2Session::start_attempt(int64_t nowMs) {
  set_state(State::Connecting);
  waitingRetry_ = false;
  stats().connectAttempts++;
  std::string err;
  if (!sctp_.start_connect(cfg_.termAddr, cfg_.termPort, cfg_.sctpSrcPort, err)) {
    attempt_failed(err, nowMs);
    return;
  }
  deadlineMs_ = nowMs + cfg_.connectTimeoutS * 1000LL;
}

void E2Session::attempt_failed(const std::string &why, int64_t nowMs) {
  stats().connectFailures++;
  ALOG_W("connect to %s:%d failed (%s); retry in %d s", cfg_.termAddr.c_str(), cfg_.termPort, why.c_str(),
         cfg_.connectRetryS);
  sctp_.close();
  waitingRetry_ = true;
  deadlineMs_ = nowMs + cfg_.connectRetryS * 1000LL;
}

int E2Session::poll_fd(short &events) const {
  if (sctp_.fd() < 0) return -1;
  events = sctp_.connecting() ? POLLOUT : POLLIN;
  return sctp_.fd();
}

void E2Session::on_poll(short revents, int64_t nowMs) {
  std::string err;
  if (sctp_.connecting()) {
    if (!sctp_.finish_connect(err)) {
      attempt_failed(err, nowMs);
      return;
    }
    Bytes setup;
    if (!build_setup_request(cfg_, ranFuncDef_, setup, err)) agent_exit(1, "E2SetupRequest: " + err);
    if (sctp_.send(setup, err) != SctpAssociation::SendResult::Sent) {
      attempt_failed("sending E2SetupRequest failed " + err, nowMs);
      return;
    }
    ALOG_I("SCTP up %s -> %s:%d; E2SetupRequest sent (%zu octets)", sctp_.local_endpoint().c_str(),
           cfg_.termAddr.c_str(), cfg_.termPort, setup.size());
    set_state(State::SetupSent);
    deadlineMs_ = nowMs + cfg_.setupTimeoutS * 1000LL;
    return;
  }
  std::vector<Bytes> msgs;
  std::string reason;
  bool alive = sctp_.read_messages(msgs, reason);
  for (const Bytes &m : msgs) handle_pdu(m);
  if (!alive) agent_exit(2, "association lost: " + reason);
  (void)revents;
}

void E2Session::handle_pdu(const Bytes &pdu) {
  stats().rxPdu++;
  InboundPdu p;
  std::string err;
  if (!decode_inbound(pdu.data(), pdu.size(), p, err)) {
    stats().rxPduUndecodable++;
    ALOG_W("undecodable E2AP PDU (%zu octets): %s", pdu.size(), err.c_str());
    return;
  }
  ALOG_I("rx %s (procedure %ld)", inbound_kind_name(p.kind), p.procedureCode);
  switch (p.kind) {
    case InboundPdu::SetupResponse: {
      if (state_ != State::SetupSent) break;
      stats().setups++;
      bool ok = std::find(p.funcsAccepted.begin(), p.funcsAccepted.end(), cfg_.ranFuncId) != p.funcsAccepted.end();
      stats().setupFuncAccepted = ok;
      ALOG_I("E2 setup done: %zu function(s) accepted, %zu rejected; RAN function %ld %s", p.funcsAccepted.size(),
             p.funcsRejected.size(), cfg_.ranFuncId, ok ? "ACCEPTED" : "NOT accepted");
      set_state(State::Ready);
      break;
    }
    case InboundPdu::SetupFailure: agent_exit(3, "E2SetupFailure received");
    case InboundPdu::SubscriptionRequest: on_subscription(p); break;
    case InboundPdu::SubscriptionDeleteRequest: {
      size_t pending = subs_.pending_samples();
      bool removed = subs_.remove(p.requestorId, p.instanceId);
      stats().samplesUnreported += pending - subs_.pending_samples();
      stats().subsDeleted += removed;
      stats().subs = subs_.size();
      ALOG_I("subscription delete %ld/%ld (%s)", p.requestorId, p.instanceId, removed ? "removed" : "unknown");
      Bytes b;
      if (build_subscription_delete_response(p.requestorId, p.instanceId, p.ranFuncId, b, err))
        send_ctrl(b, "RICsubscriptionDeleteResponse");
      else ALOG_E("delete response: %s", err.c_str());
      break;
    }
    case InboundPdu::ServiceQuery: {
      stats().serviceQueries++;
      Bytes b;
      if (build_service_update(cfg_, ranFuncDef_, p.transactionId < 0 ? 0 : p.transactionId, b, err))
        send_ctrl(b, "RICserviceUpdate");
      else ALOG_E("service update: %s", err.c_str());
      break;
    }
    case InboundPdu::ErrorIndication: stats().errorIndications++; break;
    case InboundPdu::ControlRequest:
      if (onControl_) onControl_(p);
      else stats().otherPdus++;
      break;
    default: stats().otherPdus++; break;  // ServiceUpdateAck, Reset, RICcontrol, ...: log only
  }
}

void E2Session::on_subscription(const InboundPdu &p) {
  if (p.ranFuncId != cfg_.ranFuncId) {
    stats().subsOtherFunc++;
    ALOG_W("subscription %ld/%ld for RAN function %ld ignored (agent serves %ld)", p.requestorId, p.instanceId,
           p.ranFuncId, cfg_.ranFuncId);
    return;
  }
  // T is the configured indication period, not the hello's: the subscription
  // usually arrives before ns-3 connects, and the hello must match it anyway.
  KpmAdmission a = admit_kpm_subscription(p, cfg_.indicationPeriodMs, cfg_.maxReportRecords);
  Bytes b;
  std::string err;
  if (a.refused) {
    stats().subsRefused++;
    ALOG_W("subscription %ld/%ld refused, ricRequest cause %ld: %s", p.requestorId, p.instanceId, a.refusalCause,
           a.reason.c_str());
    if (build_subscription_failure(p.requestorId, p.instanceId, p.ranFuncId, a.refusalCause, b, err))
      send_ctrl(b, "RICsubscriptionFailure");
    else ALOG_E("subscription failure: %s", err.c_str());
    return;
  }
  Subscription s;
  s.requestorId = p.requestorId;
  s.instanceId = p.instanceId;
  s.ranFuncId = p.ranFuncId;
  s.actionIds = a.admitted;
  s.actionId = *std::min_element(s.actionIds.begin(), s.actionIds.end());
  s.samplesPerReport = a.samplesPerReport;
  size_t pending = subs_.pending_samples();
  bool replaced = subs_.add_or_replace(s);
  stats().samplesUnreported += pending - subs_.pending_samples();
  (replaced ? stats().subsReplaced : stats().subsAdded)++;
  stats().actionsNotAdmitted += a.notAdmitted.size();
  stats().subs = subs_.size();
  ALOG_I("subscription %ld/%ld RAN function %ld: reporting period %lu ms = %ld x %ld ms; %zu action(s) admitted, "
         "%zu not admitted%s%s; indications on action %ld%s",
         s.requestorId, s.instanceId, s.ranFuncId, a.reportingPeriodMs, s.samplesPerReport, cfg_.indicationPeriodMs,
         s.actionIds.size(), a.notAdmitted.size(), a.reason.empty() ? "" : ": ", a.reason.c_str(), s.actionId,
         replaced ? " (replaced)" : "");
  if (build_subscription_response(s.requestorId, s.instanceId, s.ranFuncId, s.actionIds, a.notAdmitted, b, err))
    send_ctrl(b, "RICsubscriptionResponse");
  else ALOG_E("subscription response: %s", err.c_str());
}

void E2Session::send_ctrl(const Bytes &pdu, const char *what) {
  std::string err;
  SctpAssociation::SendResult r = sctp_.send(pdu, err);
  if (r == SctpAssociation::SendResult::Lost) agent_exit(2, std::string("association lost sending ") + what + ": " + err);
  if (r == SctpAssociation::SendResult::Busy) {
    stats().ctrlSendFailed++;
    ALOG_E("%s not sent: SCTP send buffer full", what);
    return;
  }
  ALOG_I("tx %s (%zu octets)", what, pdu.size());
}

bool E2Session::send_report(Subscription &sub, const EncodedReport &rep) {
  std::string err;
  auto one = [&](const Bytes &msg, bool cell) {
    Bytes ind;
    if (!build_indication(sub.requestorId, sub.instanceId, sub.ranFuncId, sub.actionId, sub.nextSn, rep.header, msg,
                          ind, err)) {
      stats().droppedEncode++;
      ALOG_E("indication: %s", err.c_str());
      return false;
    }
    SctpAssociation::SendResult r = sctp_.send(ind, err);
    if (r == SctpAssociation::SendResult::Lost) agent_exit(2, "association lost sending RICindication: " + err);
    if (r == SctpAssociation::SendResult::Busy) {
      stats().droppedSendBusy++;
      return false;
    }
    sub.nextSn = (sub.nextSn + 1) & 0xFFFF;
    stats().indTx++;
    (cell ? stats().indTxCell : stats().indTxUe)++;
    return true;
  };
  if (!one(rep.cellMsg, true)) return false;
  for (const Bytes &u : rep.ueMsgs)
    if (!one(u, false)) return false;
  return true;
}

bool E2Session::forward(const SampleRecords &r, const SampleEncoder &enc, const HelloInfo &hello) {
  PeriodTally t = subs_.add_sample(r, [&](Subscription &sub, const std::vector<SampleRecords> &samples) {
    EncodedReport rep;
    std::string err;
    if (enc.encode(samples, hello, rep, err)) return send_report(sub, rep);
    stats().droppedEncode++;
    ALOG_E("report seq %lld..%lld not encoded: %s", (long long)samples.front().seq, (long long)samples.back().seq,
           err.c_str());
    return false;
  });
  stats().reportGaps += t.gaps;
  stats().samplesGapDiscarded += t.gapDiscarded;
  stats().samplesReportFailed += t.failed;
  stats().samplesForwarded += t.forwarded;
  return t.failed == 0;
}

void E2Session::end_reports() { stats().samplesUnreported += subs_.end_periods(); }

}  // namespace agent
