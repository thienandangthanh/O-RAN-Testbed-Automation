// Unit test of the RC control path (src/rc-control.cpp) and the RC codec,
// driven by real RICcontrolRequest content: the E2SM-RC header/message octets
// rc a2282ee sent in the pre-M8 probe (tests/fixtures/rc-control-requests.hex,
// "<frame> <header_hex> <message_hex>"). Each case prints PASS/FAIL <name>;
// exit 0 only if all pass. It also prints the ACK's RIC Control Outcome octets
// (OUTCOME_HEX) and the whole ACK PDU (ACK_PDU_HEX) for the gate to decode
// with the independent decoder (tools/rc-decode) and tshark.
//
// usage: rc-control-test <fixture.hex>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "../src/agent-stats.hpp"
#include "../src/asn-util.hpp"
#include "../src/e2ap-inbound.hpp"
#include "../src/rc-control.hpp"
#include "rc-codec.h"

extern "C" {
#include "CauseRICrequest.h"
#include "E2AP-PDU.h"
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "SuccessfulOutcome.h"
#include "UnsuccessfulOutcome.h"
}

using namespace agent;

namespace {

int g_fail = 0;

void verdict(const char *name, bool ok, const std::string &detail = "") {
  printf("%s %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : ": ", detail.c_str());
  if (!ok) g_fail++;
}

Bytes from_hex(const std::string &h) {
  Bytes b;
  for (size_t i = 0; i + 1 < h.size(); i += 2) b.push_back((uint8_t)std::stoul(h.substr(i, 2), nullptr, 16));
  return b;
}

// RICcontrolRequest encoded with NIST's E2AP asn1c (the agent's own codec).
Bytes control_request(long reqId, long instId, long func, const Bytes &hdr, const Bytes &msg, long ackReq) {
  auto *pdu = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
  pdu->present = E2AP_PDU_PR_initiatingMessage;
  auto *im = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  pdu->choice.initiatingMessage = im;
  im->procedureCode = ProcedureCode_id_RICcontrol;
  im->criticality = Criticality_reject;
  im->value.present = InitiatingMessage__value_PR_RICcontrolRequest;
  auto &list = im->value.choice.RICcontrolRequest.protocolIEs.list;
  auto add = [&](long id, RICcontrolRequest_IEs__value_PR pr) {
    auto *ie = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    ie->id = id;
    ie->criticality = Criticality_reject;
    ie->value.present = pr;
    ASN_SEQUENCE_ADD(&list, ie);
    return ie;
  };
  auto *r = add(ProtocolIE_ID_id_RICrequestID, RICcontrolRequest_IEs__value_PR_RICrequestID);
  r->value.choice.RICrequestID.ricRequestorID = reqId;
  r->value.choice.RICrequestID.ricInstanceID = instId;
  add(ProtocolIE_ID_id_RANfunctionID, RICcontrolRequest_IEs__value_PR_RANfunctionID)->value.choice.RANfunctionID = func;
  OCTET_STRING_fromBuf(&add(ProtocolIE_ID_id_RICcontrolHeader, RICcontrolRequest_IEs__value_PR_RICcontrolHeader)
                            ->value.choice.RICcontrolHeader,
                       (const char *)hdr.data(), (int)hdr.size());
  OCTET_STRING_fromBuf(&add(ProtocolIE_ID_id_RICcontrolMessage, RICcontrolRequest_IEs__value_PR_RICcontrolMessage)
                            ->value.choice.RICcontrolMessage,
                       (const char *)msg.data(), (int)msg.size());
  if (ackReq >= 0)
    add(ProtocolIE_ID_id_RICcontrolAckRequest, RICcontrolRequest_IEs__value_PR_RICcontrolAckRequest)
        ->value.choice.RICcontrolAckRequest = ackReq;
  Bytes out;
  std::string err;
  if (!aper_encode(&asn_DEF_E2AP_PDU, pdu, out, err)) fprintf(stderr, "request encode: %s\n", err.c_str());
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
  return out;
}

// A decoded answer: "ack" (with outcome octets) or "failure" (with cause), echoing the request ID.
struct Answer {
  std::string kind;
  long reqId = -1, instId = -1, func = -1, cause = -1;
  Bytes outcome;
  bool ok = false;
};

Answer decode_answer(const Bytes &b) {
  Answer a;
  void *p = nullptr;
  std::string err;
  if (!aper_decode_clean(&asn_DEF_E2AP_PDU, &p, b.data(), b.size(), err)) return a;
  auto *pdu = (E2AP_PDU_t *)p;
  if (pdu->present == E2AP_PDU_PR_successfulOutcome &&
      pdu->choice.successfulOutcome->procedureCode == ProcedureCode_id_RICcontrol) {
    a.kind = "ack";
    auto &l = pdu->choice.successfulOutcome->value.choice.RICcontrolAcknowledge.protocolIEs.list;
    for (int i = 0; i < l.count; i++) {
      auto &v = l.array[i]->value;
      if (v.present == RICcontrolAcknowledge_IEs__value_PR_RICrequestID)
        a.reqId = v.choice.RICrequestID.ricRequestorID, a.instId = v.choice.RICrequestID.ricInstanceID;
      if (v.present == RICcontrolAcknowledge_IEs__value_PR_RANfunctionID) a.func = v.choice.RANfunctionID;
      if (v.present == RICcontrolAcknowledge_IEs__value_PR_RICcontrolOutcome)
        a.outcome.assign(v.choice.RICcontrolOutcome.buf, v.choice.RICcontrolOutcome.buf + v.choice.RICcontrolOutcome.size);
    }
    a.ok = true;
  } else if (pdu->present == E2AP_PDU_PR_unsuccessfulOutcome &&
             pdu->choice.unsuccessfulOutcome->procedureCode == ProcedureCode_id_RICcontrol) {
    a.kind = "failure";
    auto &l = pdu->choice.unsuccessfulOutcome->value.choice.RICcontrolFailure.protocolIEs.list;
    for (int i = 0; i < l.count; i++) {
      auto &v = l.array[i]->value;
      if (v.present == RICcontrolFailure_IEs__value_PR_RICrequestID)
        a.reqId = v.choice.RICrequestID.ricRequestorID, a.instId = v.choice.RICrequestID.ricInstanceID;
      if (v.present == RICcontrolFailure_IEs__value_PR_RANfunctionID) a.func = v.choice.RANfunctionID;
      if (v.present == RICcontrolFailure_IEs__value_PR_Cause && v.choice.Cause.present == Cause_PR_ricRequest)
        a.cause = v.choice.Cause.choice.ricRequest;
    }
    a.ok = true;
  }
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  return a;
}

struct Harness {
  std::vector<Bytes> e2;
  std::vector<std::string> ipc;
  bool ipcUp = true;
  RcControlPath rc{2, [this](const Bytes &b, const char *) { e2.push_back(b); },
                   [this](const std::string &l) {
                     if (!ipcUp) return false;
                     ipc.push_back(l);
                     return true;
                   }};
  void request(const Bytes &pdu, int64_t afterSeq = 7) {
    InboundPdu p;
    std::string err;
    if (!decode_inbound(pdu.data(), pdu.size(), p, err) || p.kind != InboundPdu::ControlRequest)
      fprintf(stderr, "inbound decode: %s\n", err.c_str());
    rc.on_request(p, afterSeq, ipcUp);
  }
  void ack(uint64_t ctlId, const char *outcome, const char *cause = "") {
    rc.on_control_ack({{"type", "controlAck"}, {"nodeId", 2}, {"ctlId", ctlId}, {"outcome", outcome}, {"cause", cause}});
  }
};

bool one_failure(const Harness &h, long cause, long reqId) {
  if (h.e2.size() != 1 || !h.ipc.empty()) return false;
  Answer a = decode_answer(h.e2[0]);
  return a.ok && a.kind == "failure" && a.cause == cause && a.reqId == reqId;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <fixture.hex>\n", argv[0]);
    return 2;
  }
  std::ifstream f(argv[1]);
  std::string line, frame, hh, mh;
  std::vector<std::pair<Bytes, Bytes>> fx;
  while (std::getline(f, line)) {
    std::istringstream is(line);
    if (is >> frame >> hh >> mh) fx.emplace_back(from_hex(hh), from_hex(mh));
  }
  verdict("fixture-loaded", !fx.empty(), std::to_string(fx.size()) + " PDUs");
  if (fx.empty()) return 1;

  // Every fixture PDU decodes with the agent's codec: style 3, action 1, cell 3, and
  // AMF-UE-NGAP-ID k+1 on line k (the probe numbered its calls; tools/rc-decode agrees).
  int good = 0;
  for (size_t k = 0; k < fx.size(); k++) {
    auto &p = fx[k];
    rcc_control c;
    char err[256];
    TargetCell t;
    std::string terr;
    if (rcc_decode_control(p.first.data(), p.first.size(), p.second.data(), p.second.size(), &c, err, sizeof err) == 0 &&
        c.style == 3 && c.action == 1 && c.amfUeNgapId == k + 1 && parse_target_octets(c.targetOctets, c.targetLen, t, terr) &&
        t.cellId == 3 && t.gnbId == 0)
      good++;
  }
  verdict("fixture-decodes", good == (int)fx.size(), std::to_string(good) + "/" + std::to_string(fx.size()));

  const Bytes &hdr = fx[0].first, &msg = fx[0].second;
  // N5 key 0000000202 (gNB 2, cell 2) as rc sends it: 00 | PLMN | key.
  const uint8_t key[9] = {0x00, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x02, 0x02};
  uint8_t buf[256];
  long n = rcc_test_reencode_target(msg.data(), msg.size(), key, sizeof key, buf, sizeof buf);
  Bytes msg202(buf, buf + (n > 0 ? n : 0));
  {
    rcc_control c;
    char err[256];
    TargetCell t;
    std::string terr;
    bool ok = n > 0 && rcc_decode_control(hdr.data(), hdr.size(), msg202.data(), msg202.size(), &c, err, sizeof err) == 0 &&
              parse_target_octets(c.targetOctets, c.targetLen, t, terr) && t.cellId == 2 && t.gnbId == 2;
    verdict("target-key-0000000202", ok);
  }

  {  // RAN function 2 (KPM) -> ran-function-id-invalid, nothing to ns-3
    Harness h;
    h.request(control_request(11, 1, 2, hdr, msg, -1));
    verdict("ran-function-id-invalid", one_failure(h, CauseRICrequest_ran_function_id_invalid, 11));
  }
  {  // truncated message -> control-message-invalid
    Harness h;
    Bytes bad(msg.begin(), msg.end() - 3);
    h.request(control_request(12, 1, 3, hdr, bad, -1));
    verdict("control-message-invalid", one_failure(h, CauseRICrequest_control_message_invalid, 12));
  }
  {  // action 2 (Conditional Handover) -> action-not-supported
    Harness h;
    long hn = rcc_test_reencode_header(hdr.data(), hdr.size(), 3, 2, buf, sizeof buf);
    h.request(control_request(13, 1, 3, Bytes(buf, buf + (hn > 0 ? hn : 0)), msg, -1));
    verdict("action-not-supported", hn > 0 && one_failure(h, CauseRICrequest_action_not_supported, 13));
  }
  {  // ns-3 not connected -> control-failed-to-execute at once
    Harness h;
    h.ipcUp = false;
    h.request(control_request(14, 1, 3, hdr, msg, -1));
    verdict("ipc-down-control-failed-to-execute", one_failure(h, CauseRICrequest_control_failed_to_execute, 14));
  }
  {  // forwarded control line, then applied -> ACK with ControlOutcome Format 1
    Harness h;
    h.request(control_request(15, 2, 3, hdr, msg202, -1), 41);
    nlohmann::json j = h.ipc.empty() ? nlohmann::json() : nlohmann::json::parse(h.ipc[0]);
    bool fwd = h.e2.empty() && h.ipc.size() == 1 && j.value("type", "") == "control" && j.value("nodeId", 0) == 2 &&
               j.value("ctlId", 0) == 1 && j.value("imsi", 0) == 1 && j.value("targetCellId", 0) == 2 &&
               j.value("afterSeq", 0) == 41 && j["ric"].value("requestorId", 0) == 15 && h.rc.pending() == 1;
    verdict("forward-control-line", fwd, h.ipc.empty() ? "" : h.ipc[0].substr(0, h.ipc[0].size() - 1));
    h.ack(1, "applied");
    Answer a = h.e2.size() == 1 ? decode_answer(h.e2[0]) : Answer{};
    bool ok = a.ok && a.kind == "ack" && a.reqId == 15 && a.instId == 2 && a.func == 3 && a.outcome == Bytes{0x00, 0x00} &&
              h.rc.pending() == 0;
    verdict("format1-on-ack", ok);
    if (a.ok) {
      printf("OUTCOME_HEX %s\n", to_hex(a.outcome).c_str());
      printf("ACK_PDU_HEX %s\n", to_hex(h.e2[0]).c_str());
    }
  }
  {  // ns-3 refuses -> control-failed-to-execute
    Harness h;
    h.request(control_request(16, 1, 3, hdr, msg, -1));
    h.ack(1, "refused", "alreadyOnTarget");
    bool ok = h.e2.size() == 1 && decode_answer(h.e2[0]).cause == CauseRICrequest_control_failed_to_execute;
    verdict("control-failed-to-execute", ok);
  }
  {  // bye with 3 pending -> 3 FAILUREs, each once
    Harness h;
    for (long r = 20; r < 23; r++) h.request(control_request(r, 1, 3, hdr, msg, -1));
    h.rc.fail_all_pending("bye");
    h.rc.fail_all_pending("bye again");
    bool ok = h.e2.size() == 3 && h.rc.pending() == 0;
    for (size_t i = 0; ok && i < 3; i++) {
      Answer a = decode_answer(h.e2[i]);
      ok = a.kind == "failure" && a.cause == CauseRICrequest_control_failed_to_execute && a.reqId == 20 + (long)i;
    }
    verdict("bye-fails-all-pending", ok);
  }
  {  // RIC Control Ack Request = NoAck and applied -> no message (E2AP v03.00 8.2.4.2)
    Harness h;
    h.request(control_request(30, 1, 3, hdr, msg, 0));
    h.ack(1, "applied");
    verdict("noack-applied-sends-nothing", h.e2.empty() && h.rc.pending() == 0);
  }
  {  // ns-3 answers a control that arrived after the last barrier as late -> one FAILURE
     // control-failed-to-execute, also under NoAck (it suppresses only the ACK)
    bool ok = true;
    for (long ackReq : {-1L, 0L}) {
      Harness h;
      h.request(control_request(32, 1, 3, hdr, msg, ackReq));
      h.ack(1, "refused", "late");
      h.ack(1, "refused", "late");
      Answer a = h.e2.size() == 1 ? decode_answer(h.e2[0]) : Answer{};
      ok = ok && a.ok && a.kind == "failure" && a.cause == CauseRICrequest_control_failed_to_execute && a.reqId == 32 &&
           h.rc.pending() == 0;
    }
    verdict("late-refusal-control-failed-to-execute", ok);
  }
  {  // an ack for an unknown ctlId answers nothing; a repeated ack answers once
    Harness h;
    h.request(control_request(31, 1, 3, hdr, msg, -1));
    h.ack(9, "applied");
    h.ack(1, "applied");
    h.ack(1, "applied");
    verdict("exactly-one-answer", h.e2.size() == 1 && stats().ctlAckUnknown >= 2);
  }
  printf("rc-control-test: %s\n", g_fail ? "FAIL" : "ok");
  return g_fail ? 1 : 0;
}
