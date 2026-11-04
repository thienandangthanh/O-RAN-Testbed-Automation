// Unit test of the RC control path (src/rc-control.cpp) and the RC codec. Two
// fixtures, lines "<id> <header_hex> <message_hex>":
//   - tests/fixtures/rc-control-nrcgi.hex: X.691 octets from the independent
//     codec (tests/make-rc-control-fixtures.py, pycrate). Positives
//     "s5a3-x2ap<X>-mn<M>-gnb<n>": Style 5 action 3, UE ID en-gNB-UEID
//     {m-eNB-UE-X2AP-ID X, globalENB-ID {00F110, macro eNB ID M}}, target = the
//     APER NR-CGI of gNB n (NR Cell Identity = gNB ID n, cell part 1); the header and message equal what rc
//     with the Testbed patch set sends. Negatives "invalid-*" (refused
//     control-message-invalid) and "unsupported-*" (action-not-supported);
//   - tests/fixtures/rc-control-requests.hex: the 30 RICcontrolRequests rc
//     a2282ee sent in the pre-M8 probe, with the unbounded RANParameter-ID
//     encoding and the 9-octet pre-R-3 target; every one must be refused.
// Each case prints PASS/FAIL <name>;
// exit 0 only if all pass. It also prints the ACK's RIC Control Outcome octets
// (OUTCOME_HEX) and the whole ACK PDU (ACK_PDU_HEX) for the gate to decode
// with the independent decoder (tools/rc-decode) and tshark.
//
// usage: rc-control-test <m8-fixture.hex> <nrcgi-fixture.hex>
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
  RcControlPath rc;
  // announced: the node announces RAN function 3 (a gNB agent); false is the eNB agent
  explicit Harness(bool announced = true)
      : rc(2, {0x00, 0xF1, 0x10}, announced, [this](const Bytes &b, const char *) { e2.push_back(b); },
           [this](const std::string &l) {
             if (!ipcUp) return false;
             ipc.push_back(l);
             return true;
           }) {}
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

struct FixtureLine {
  std::string id;
  Bytes header, message;
};

std::vector<FixtureLine> load_fixture(const char *path) {
  std::ifstream f(path);
  std::string line;
  std::vector<FixtureLine> fx;
  while (std::getline(f, line)) {
    std::istringstream is(line);
    std::string id, hh, mh;
    if (is >> id >> hh >> mh) fx.push_back({id, from_hex(hh), from_hex(mh)});
  }
  return fx;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <m8-fixture.hex> <nrcgi-fixture.hex>\n", argv[0]);
    return 2;
  }
  const std::vector<FixtureLine> m8 = load_fixture(argv[1]), x691 = load_fixture(argv[2]);
  verdict("fixture-loaded", m8.size() == 30 && !x691.empty(),
          std::to_string(m8.size()) + " M8 PDUs, " + std::to_string(x691.size()) + " X.691 PDUs");
  if (m8.empty() || x691.empty()) return 1;

  // Every positive X.691 line decodes with the agent's codec: style 5, action 3, en-gNB-UEID with the X2AP ID X, the
  // PLMN 00F110 and the macro eNB ID M, and the NR-CGI of gNB n named by its id "s5a3-x2ap<X>-mn<M>-gnb<n>".
  int good = 0, positives = 0;
  const FixtureLine *gnb3 = nullptr;
  std::vector<const FixtureLine *> pos;
  for (const auto &p : x691) {
    unsigned long x2 = 0, mn = 0, gnb = 0;
    rcc_control c;
    char err[256];
    char want[19];
    if (sscanf(p.id.c_str(), "s5a3-x2ap%lu-mn%lx-gnb%lu", &x2, &mn, &gnb) != 3) continue;
    positives++;
    pos.push_back(&p);
    snprintf(want, sizeof want, "0000f110%08lx10", gnb);
    if (rcc_decode_control(p.header.data(), p.header.size(), p.message.data(), p.message.size(), &c, err, sizeof err) ==
            0 &&
        c.style == 5 && c.action == 3 && c.enGnbUeId && c.mEnbUeX2apId == x2 && c.macroEnbId == mn &&
        Bytes(c.globalEnbPlmn, c.globalEnbPlmn + 3) == Bytes{0x00, 0xF1, 0x10} &&
        Bytes(c.targetOctets, c.targetOctets + c.targetLen) == from_hex(want))
      good++;
    if (gnb == 3 && x2 == 5 && mn == 1) gnb3 = &p;
  }
  verdict("fixture-decodes", positives >= 3 && good == positives && gnb3,
          std::to_string(good) + "/" + std::to_string(positives) + " Style 5 action 3 X.691 PDUs");
  if (!gnb3) return 1;

  const Bytes &hdr = gnb3->header, &msg = gnb3->message;
  uint8_t buf[256];
  auto with_target = [&](const char *hex) {
    Bytes t = from_hex(hex);
    long n = rcc_test_reencode_target(msg.data(), msg.size(), t.data(), t.size(), buf, sizeof buf);
    return Bytes(buf, buf + (n > 0 ? n : 0));
  };
  // The agent's codec re-encodes the gNB 3 message to the same X.691 octets.
  verdict("agent-codec-reencode-equals-x691", with_target("0000f1100000000310") == msg);
  {
    TargetCell t;
    std::string terr;
    Bytes o = from_hex("0000f1100000000310");
    bool ok = !msg.empty() && parse_target_nr_cgi(o.data(), o.size(), {0x00, 0xF1, 0x10}, t, terr) && t.gnbId == 3 &&
              t.cellId == 3;
    verdict("nrcgi-target-gnb3", ok, terr);
  }
  {  // the N5 form 00|PLMN|gNB-ID|cell (gNB 3 cell 3): nonzero padding, no canonical NR CGI -> refused
    Harness h;
    h.request(control_request(17, 1, 3, hdr, with_target("0000f1100000000303"), -1));
    verdict("n5-target-refused", one_failure(h, CauseRICrequest_control_message_invalid, 17));
  }
  {  // every request exactly as rc a2282ee sent it in M8 -> refused
    int refused = 0;
    for (size_t k = 0; k < m8.size(); k++) {
      Harness h;
      h.request(control_request(18, 1, 3, m8[k].header, m8[k].message, -1));
      refused += one_failure(h, CauseRICrequest_control_message_invalid, 18) ? 1 : 0;
    }
    verdict("m8-capture-refused", refused == (int)m8.size(),
            std::to_string(refused) + "/" + std::to_string(m8.size()) + " control-message-invalid");
  }
  {  // another PLMN (00F220) or cell part 2 -> refused
    Harness h1, h2;
    h1.request(control_request(19, 1, 3, hdr, with_target("0000f2200000000310"), -1));
    h2.request(control_request(19, 2, 3, hdr, with_target("0000f1100000000320"), -1));
    verdict("nrcgi-wrong-plmn-or-cell-part-refused", one_failure(h1, CauseRICrequest_control_message_invalid, 19) &&
                                                          one_failure(h2, CauseRICrequest_control_message_invalid, 19));
  }

  {  // each independently encoded negative: invalid-* -> control-message-invalid, unsupported-* ->
     // action-not-supported; nothing reaches ns-3
    int n = 0, ok = 0;
    std::string bad;
    for (const auto &p : x691) {
      long cause = p.id.rfind("invalid-", 0) == 0       ? CauseRICrequest_control_message_invalid
                   : p.id.rfind("unsupported-", 0) == 0 ? CauseRICrequest_action_not_supported
                                                         : -1;
      if (cause < 0) continue;
      n++;
      Harness h;
      h.request(control_request(40, 1, 3, p.header, p.message, -1));
      if (one_failure(h, cause, 40)) ok++;
      else bad += " " + p.id;
    }
    verdict("independent-negatives-refused", n >= 9 && ok == n,
            std::to_string(ok) + "/" + std::to_string(n) + (bad.empty() ? "" : ", not refused as expected:" + bad));
  }
  {  // RAN function 2 (KPM) -> ran-function-id-invalid, nothing to ns-3
    Harness h;
    h.request(control_request(11, 1, 2, hdr, msg, -1));
    verdict("ran-function-id-invalid", one_failure(h, CauseRICrequest_ran_function_id_invalid, 11));
  }
  {  // the eNB agent does not announce RAN function 3: a well-formed Style 5/3 control -> ran-function-id-invalid
    Harness h(false);
    const uint64_t before = stats().ctlRejFunc;
    h.request(control_request(10, 1, 3, hdr, msg, -1));
    verdict("enb-refuses-ran-function-id-invalid",
            one_failure(h, CauseRICrequest_ran_function_id_invalid, 10) && stats().ctlRejFunc == before + 1 &&
                h.rc.pending() == 0);
  }
  {  // the definition of RAN function 3: Style 5 action 3 only, with RAN parameters 1-4
    uint8_t def[1024];
    char sum[256] = {0};
    long n = rcc_encode_ran_function_definition(def, sizeof def);
    bool ok = n > 0 && rcc_test_ran_function_definition_summary(def, (size_t)n, sum, sizeof sum) == 0 &&
              std::string(sum) == "5/3:1,2,3,4;";
    verdict("ran-function-definition-style5-action3-only", ok, sum);
  }
  {  // truncated message -> control-message-invalid
    Harness h;
    Bytes bad(msg.begin(), msg.end() - 3);
    h.request(control_request(12, 1, 3, hdr, bad, -1));
    verdict("control-message-invalid", one_failure(h, CauseRICrequest_control_message_invalid, 12));
  }
  {  // Style 3 action 1 (Handover Control) and Style 5 action 4 with the same en-gNB-UEID -> action-not-supported
    bool ok = true;
    for (auto sa : {std::pair<long, long>{3, 1}, {5, 4}}) {
      Harness h;
      long hn = rcc_test_reencode_header(hdr.data(), hdr.size(), sa.first, sa.second, buf, sizeof buf);
      h.request(control_request(13, 1, 3, Bytes(buf, buf + (hn > 0 ? hn : 0)), msg, -1));
      ok = ok && hn > 0 && one_failure(h, CauseRICrequest_action_not_supported, 13);
    }
    verdict("action-not-supported", ok);
  }
  {  // ns-3 not connected -> control-failed-to-execute at once
    Harness h;
    h.ipcUp = false;
    h.request(control_request(14, 1, 3, hdr, msg, -1));
    verdict("ipc-down-control-failed-to-execute", one_failure(h, CauseRICrequest_control_failed_to_execute, 14));
  }
  {  // forwarded control line, then applied -> ACK with ControlOutcome Format 1
    Harness h;
    h.request(control_request(15, 2, 3, hdr, msg, -1), 41);
    nlohmann::json j = h.ipc.empty() ? nlohmann::json() : nlohmann::json::parse(h.ipc[0]);
    // the line names the UE by the decoded en-gNB-UEID members, in this key order, and carries no IMSI
    std::vector<std::string> keys;
    const nlohmann::ordered_json ordered = h.ipc.empty() ? nlohmann::ordered_json() : nlohmann::ordered_json::parse(h.ipc[0]);
    for (const auto &kv : ordered.items()) keys.push_back(kv.key());
    bool fwd = h.e2.empty() && h.ipc.size() == 1 && j.value("type", "") == "control" && j.value("v", 0) == 1 &&
               j.value("nodeId", 0) == 2 && j.value("ctlId", 0) == 1 && j.value("style", 0) == 5 &&
               j.value("action", 0) == 3 && j["ueId"] == nlohmann::json({{"mEnbUeX2apId", 5}, {"mnCellId", 1}}) &&
               !j.contains("imsi") && j.value("targetCellId", 0) == 3 && j["diag"].value("targetGnbId", 0) == 3 &&
               j.value("afterSeq", 0) == 41 && j["ric"].value("requestorId", 0) == 15 && h.rc.pending() == 1 &&
               keys == std::vector<std::string>{"type", "v", "nodeId", "ctlId", "ric", "style", "action", "ueId",
                                                "targetCellId", "afterSeq", "diag"};
    verdict("nrcgi-applied-path", fwd, h.ipc.empty() ? "" : h.ipc[0].substr(0, h.ipc[0].size() - 1));
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
  {  // every positive line is forwarded with the X2AP ID and macro eNB ID it carries (range edges 0, 4095, FFFFF)
    int ok = 0;
    for (const FixtureLine *p : pos) {
      unsigned long x2 = 0, mn = 0, gnb = 0;
      sscanf(p->id.c_str(), "s5a3-x2ap%lu-mn%lx-gnb%lu", &x2, &mn, &gnb);
      Harness h;
      h.request(control_request(16, 1, 3, p->header, p->message, -1));
      nlohmann::json j = h.ipc.size() == 1 ? nlohmann::json::parse(h.ipc[0]) : nlohmann::json();
      if (h.e2.empty() && h.ipc.size() == 1 &&
          j["ueId"] == nlohmann::json({{"mEnbUeX2apId", x2}, {"mnCellId", mn}}) && j.value("targetCellId", 0UL) == gnb)
        ok++;
    }
    verdict("ue-id-values-forwarded", ok == (int)pos.size(), std::to_string(ok) + "/" + std::to_string(pos.size()));
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
