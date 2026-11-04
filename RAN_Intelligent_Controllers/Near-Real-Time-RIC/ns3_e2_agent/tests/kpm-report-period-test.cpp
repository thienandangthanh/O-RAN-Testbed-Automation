// KPM reporting period / granularity test. Checks, with the agent's own code:
//   tt-*        at P = T (one sample per report) the header and message octets
//               are byte-identical to the committed golden (fixtures/kpm-tt-golden-*.txt):
//               header and cell pieces from the encoder before reporting periods
//               existed, UE pieces from the en-gNB-UEID encoder;
//   p1000-*     P = 1000 ms, G = T = 100 ms (kpimon's own action definition):
//               admitted; one report of 10 samples whose measData item t equals,
//               octet for octet, the T/T message of sample t (absent UE: noValue);
//   p150-*      P = 150 ms: RIC SUBSCRIPTION FAILURE, ricRequest
//               eventTriggerNotSupported;
//   g200-*      G = 200 ms: not admitted, ricRequest action-not-supported
//               (alone: RIC SUBSCRIPTION FAILURE; with an admitted action: in the
//               response's not-admitted list);
//   k20-*/k21-* K = P / T bound (E2_MAX_REPORT_RECORDS, default 20): K = 20
//               admitted, its worst-case cell and UE messages (every UE in every
//               sample) within E2_MAX_E2SM_BYTES; K = 21 and P = 10000 ms
//               refused: RIC SUBSCRIPTION FAILURE, ricRequest function-resource-limit;
//   period-*    the reporting periods of the subscription table: aligned to the
//               first sample a subscription sees, P / T samples in seq order per
//               report, a seq gap restarts the period, a period cut by bye is not
//               reported, and samplesIn == forwarded + gapDiscarded + failed +
//               unreported;
// Before each fixture sample the test feeds the ueContext ns-3 would send: every
// UE of the sample with lteRnti = imsi (synthetic, so the decoded
// m-eNB-UE-X2AP-ID names the IMSI), mnCellId 1 and mmeUeS1apId = imsi.
// It also writes the octets for decoding with kpimon's library
// (tools/kpimon-decode-harness, ind-lines.txt) and with the independent pycrate
// codec (tools/asn1-indep, tests/check-report-period.py).
//
// usage: kpm-report-period-test <metric-map.json> <fixtures-dir> <out-dir>
// Prints one PASS/FAIL line per check and "kpm-report-period-test: ok" or exit 1.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "../src/agent-stats.hpp"
#include "../src/e2ap-builders.hpp"
#include "../src/e2ap-inbound.hpp"
#include "../src/kpm-subscription-admission.hpp"
#include "../src/sample-forwarder.hpp"
#include "../src/subscription-table.hpp"

extern "C" {
#include "CauseRICrequest.h"
#include "E2AP-PDU.h"
#include "E2SM-KPM-ActionDefinition-Format1.h"
#include "E2SM-KPM-ActionDefinition.h"
#include "E2SM-KPM-EventTriggerDefinition-Format1.h"
#include "E2SM-KPM-EventTriggerDefinition.h"
#include "E2SM-KPM-IndicationMessage-Format1.h"
#include "E2SM-KPM-IndicationMessage-Format2.h"
#include "E2SM-KPM-IndicationMessage.h"
#include "InitiatingMessage.h"
#include "LabelInfoItem.h"
#include "MatchingUEidItem.h"
#include "MatchingUEidList.h"
#include "MeasurementCondUEidItem.h"
#include "MeasurementDataItem.h"
#include "MeasurementInfoItem.h"
#include "MeasurementRecordItem.h"
#include "ProtocolIE-Field.h"
#include "SuccessfulOutcome.h"
#include "UEID-EN-GNB.h"
#include "UEID.h"
#include "UnsuccessfulOutcome.h"
}

using namespace agent;
using nlohmann::json;

namespace {

int failures = 0;
std::string outDir;

void check(bool ok, const std::string &what) {
  printf("%s %s\n", ok ? "PASS" : "FAIL", what.c_str());
  if (!ok) failures++;
}

Bytes from_hex(const std::string &h) {
  Bytes b;
  for (size_t i = 0; i + 1 < h.size(); i += 2) b.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
  return b;
}

// "<key...> <hex>" lines of a fixture (comments skipped): key = all but the last field.
std::map<std::string, std::string> read_keyed(const std::string &path) {
  std::map<std::string, std::string> m;
  std::ifstream in(path);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    size_t sp = line.rfind(' ');
    m[line.substr(0, sp)] = line.substr(sp + 1);
  }
  return m;
}

void write_hex(const std::string &name, const Bytes &b) { std::ofstream(outDir + "/" + name + ".hex") << to_hex(b) << "\n"; }

// ---- E2SM-KPM action definition Format 1 (agent asn1c), for a non-kpimon format ----
Bytes action_format1(unsigned long granulMs) {
  auto *d = (E2SM_KPM_ActionDefinition_t *)calloc(1, sizeof(E2SM_KPM_ActionDefinition_t));
  auto *f1 = (E2SM_KPM_ActionDefinition_Format1_t *)calloc(1, sizeof(E2SM_KPM_ActionDefinition_Format1_t));
  d->ric_Style_Type = 1;
  d->actionDefinition_formats.present = E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format1;
  d->actionDefinition_formats.choice.actionDefinition_Format1 = f1;
  auto *info = (MeasurementInfoItem_t *)calloc(1, sizeof(MeasurementInfoItem_t));
  info->measType.present = MeasurementType_PR_measID;
  info->measType.choice.measID = 1;
  auto *lab = (LabelInfoItem_t *)calloc(1, sizeof(LabelInfoItem_t));
  lab->measLabel.noLabel = (long *)calloc(1, sizeof(long));
  ASN_SEQUENCE_ADD(&info->labelInfoList.list, lab);
  ASN_SEQUENCE_ADD(&f1->measInfoList.list, info);
  f1->granulPeriod = granulMs;
  Bytes out;
  std::string err;
  if (!aper_encode(&asn_DEF_E2SM_KPM_ActionDefinition, d, out, err)) fprintf(stderr, "action format1: %s\n", err.c_str());
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, d);
  return out;
}

// ---- E2SM-KPM event trigger Format 1 (agent asn1c), for periods kpimon's fixture lacks ----
Bytes event_trigger(unsigned long periodMs) {
  auto *t = (E2SM_KPM_EventTriggerDefinition_t *)calloc(1, sizeof(E2SM_KPM_EventTriggerDefinition_t));
  auto *f1 = (E2SM_KPM_EventTriggerDefinition_Format1_t *)calloc(1, sizeof(E2SM_KPM_EventTriggerDefinition_Format1_t));
  t->eventDefinition_formats.present = E2SM_KPM_EventTriggerDefinition__eventDefinition_formats_PR_eventDefinition_Format1;
  t->eventDefinition_formats.choice.eventDefinition_Format1 = f1;
  f1->reportingPeriod = periodMs;
  Bytes out;
  std::string err;
  if (!aper_encode(&asn_DEF_E2SM_KPM_EventTriggerDefinition, t, out, err)) fprintf(stderr, "event trigger: %s\n", err.c_str());
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_EventTriggerDefinition, t);
  return out;
}

// ---- RICsubscriptionRequest (as SubMgr sends it) ----
struct Action {
  long id;
  long type;  // RICactionType
  const Bytes *definition;  // nullptr: IE absent
};

Bytes subscription_request(long requestorId, const Bytes &trigger, const std::vector<Action> &actions) {
  auto *pdu = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
  pdu->present = E2AP_PDU_PR_initiatingMessage;
  auto *im = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  pdu->choice.initiatingMessage = im;
  im->procedureCode = ProcedureCode_id_RICsubscription;
  im->criticality = Criticality_reject;
  im->value.present = InitiatingMessage__value_PR_RICsubscriptionRequest;
  auto &list = im->value.choice.RICsubscriptionRequest.protocolIEs.list;
  auto add = [&list](long id) {
    auto *ie = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
    ie->id = id;
    ie->criticality = Criticality_reject;
    ASN_SEQUENCE_ADD(&list, ie);
    return ie;
  };
  auto *req = add(ProtocolIE_ID_id_RICrequestID);
  req->value.present = RICsubscriptionRequest_IEs__value_PR_RICrequestID;
  req->value.choice.RICrequestID.ricRequestorID = requestorId;
  req->value.choice.RICrequestID.ricInstanceID = 1;
  auto *fn = add(ProtocolIE_ID_id_RANfunctionID);
  fn->value.present = RICsubscriptionRequest_IEs__value_PR_RANfunctionID;
  fn->value.choice.RANfunctionID = 2;
  auto *det = add(ProtocolIE_ID_id_RICsubscriptionDetails);
  det->value.present = RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails;
  RICsubscriptionDetails_t &d = det->value.choice.RICsubscriptionDetails;
  OCTET_STRING_fromBuf(&d.ricEventTriggerDefinition, (const char *)trigger.data(), (int)trigger.size());
  for (const Action &a : actions) {
    auto *it = (RICaction_ToBeSetup_ItemIEs_t *)calloc(1, sizeof(RICaction_ToBeSetup_ItemIEs_t));
    it->id = ProtocolIE_ID_id_RICaction_ToBeSetup_Item;
    it->criticality = Criticality_ignore;
    it->value.present = RICaction_ToBeSetup_ItemIEs__value_PR_RICaction_ToBeSetup_Item;
    RICaction_ToBeSetup_Item_t &item = it->value.choice.RICaction_ToBeSetup_Item;
    item.ricActionID = a.id;
    item.ricActionType = a.type;
    if (a.definition)
      item.ricActionDefinition = OCTET_STRING_new_fromBuf(&asn_DEF_RICactionDefinition,
                                                          (const char *)a.definition->data(), (int)a.definition->size());
    ASN_SEQUENCE_ADD(&d.ricAction_ToBeSetup_List.list, it);
  }
  Bytes out;
  std::string err;
  if (!aper_encode(&asn_DEF_E2AP_PDU, pdu, out, err)) fprintf(stderr, "subscription request: %s\n", err.c_str());
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
  return out;
}

// Decodes the request octets as the agent does and decides.
KpmAdmission admit(const std::string &name, const Bytes &request, InboundPdu &p) {
  write_hex("e2ap-" + name + "-request", request);
  std::string err;
  bool ok = decode_inbound(request.data(), request.size(), p, err);
  check(ok && p.kind == InboundPdu::SubscriptionRequest, name + ": request decodes as RICsubscriptionRequest " + err);
  return admit_kpm_subscription(p, 100, Config{}.maxReportRecords);
}

// Answer PDU as the agent sends it, decoded again (caller frees).
E2AP_PDU_t *answer(const std::string &name, const InboundPdu &p, const KpmAdmission &a) {
  Bytes b;
  std::string err;
  bool built = a.refused ? build_subscription_failure(p.requestorId, p.instanceId, p.ranFuncId, a.refusalCause, b, err)
                         : build_subscription_response(p.requestorId, p.instanceId, p.ranFuncId, a.admitted,
                                                       a.notAdmitted, b, err);
  check(built, name + ": answer built " + err);
  write_hex("e2ap-" + name + "-answer", b);
  void *pdu = nullptr;
  bool ok = aper_decode_clean(&asn_DEF_E2AP_PDU, &pdu, b.data(), b.size(), err);
  check(ok, name + ": answer decodes cleanly (" + std::to_string(b.size()) + " octets) " + err);
  if (!ok) {
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return nullptr;
  }
  return (E2AP_PDU_t *)pdu;
}

// Checks a RICsubscriptionFailure: procedure 8, the request's requestor ID, the ricRequest cause.
void expect_failure(const std::string &name, const InboundPdu &p, const KpmAdmission &a, long cause) {
  check(a.refused && a.refusalCause == cause,
        name + ": refused with ricRequest cause " + std::to_string(cause) + " (" + a.reason + ")");
  E2AP_PDU_t *pdu = answer(name, p, a);
  if (!pdu) return;
  bool shape = pdu->present == E2AP_PDU_PR_unsuccessfulOutcome &&
               pdu->choice.unsuccessfulOutcome->procedureCode == ProcedureCode_id_RICsubscription &&
               pdu->choice.unsuccessfulOutcome->value.present == UnsuccessfulOutcome__value_PR_RICsubscriptionFailure;
  long got = -1, req = -1;
  if (shape) {
    auto &l = pdu->choice.unsuccessfulOutcome->value.choice.RICsubscriptionFailure.protocolIEs.list;
    for (int i = 0; i < l.count; i++) {
      if (l.array[i]->value.present == RICsubscriptionFailure_IEs__value_PR_Cause &&
          l.array[i]->value.choice.Cause.present == Cause_PR_ricRequest)
        got = l.array[i]->value.choice.Cause.choice.ricRequest;
      if (l.array[i]->value.present == RICsubscriptionFailure_IEs__value_PR_RICrequestID)
        req = l.array[i]->value.choice.RICrequestID.ricRequestorID;
    }
  }
  check(shape && got == cause && req == p.requestorId,
        name + ": RICsubscriptionFailure (procedure 8) for requestor " + std::to_string(p.requestorId) +
            ", Cause ricRequest " + std::to_string(got));
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
}

// Checks a RICsubscriptionResponse's admitted and not-admitted lists.
void expect_response(const std::string &name, const InboundPdu &p, const KpmAdmission &a, const std::vector<long> &adm,
                     const std::vector<std::pair<long, long>> &notAdm) {
  check(!a.refused && a.admitted == adm && a.notAdmitted == notAdm, name + ": admission decision (" + a.reason + ")");
  E2AP_PDU_t *pdu = answer(name, p, a);
  if (!pdu) return;
  std::vector<long> gotAdm;
  std::vector<std::pair<long, long>> gotNot;
  bool shape = pdu->present == E2AP_PDU_PR_successfulOutcome &&
               pdu->choice.successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionResponse;
  if (shape) {
    auto &l = pdu->choice.successfulOutcome->value.choice.RICsubscriptionResponse.protocolIEs.list;
    for (int i = 0; i < l.count; i++) {
      if (l.array[i]->value.present == RICsubscriptionResponse_IEs__value_PR_RICaction_Admitted_List) {
        auto &al = l.array[i]->value.choice.RICaction_Admitted_List.list;
        for (int k = 0; k < al.count; k++)
          gotAdm.push_back(
              ((RICaction_Admitted_ItemIEs_t *)al.array[k])->value.choice.RICaction_Admitted_Item.ricActionID);
      }
      if (l.array[i]->value.present == RICsubscriptionResponse_IEs__value_PR_RICaction_NotAdmitted_List) {
        auto &nl = l.array[i]->value.choice.RICaction_NotAdmitted_List.list;
        for (int k = 0; k < nl.count; k++) {
          auto &it = ((RICaction_NotAdmitted_ItemIEs_t *)nl.array[k])->value.choice.RICaction_NotAdmitted_Item;
          gotNot.emplace_back(it.ricActionID, it.cause.present == Cause_PR_ricRequest ? it.cause.choice.ricRequest : -1);
        }
      }
    }
  }
  check(shape && gotAdm == adm && gotNot == notAdm,
        name + ": RICsubscriptionResponse admits " + std::to_string(gotAdm.size()) + ", not admitted " +
            std::to_string(gotNot.size()) + " (ricRequest action-not-supported)");
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
}

// ---- KPM message decoding for the record comparisons ----
E2SM_KPM_IndicationMessage_t *decode_msg(const Bytes &b) {
  void *p = nullptr;
  std::string err;
  if (!aper_decode_clean(&asn_DEF_E2SM_KPM_IndicationMessage, &p, b.data(), b.size(), err)) {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, p);
    return nullptr;
  }
  return (E2SM_KPM_IndicationMessage_t *)p;
}

Bytes enc_record(const MeasurementRecordItem_t *r) {
  Bytes b;
  std::string err;
  aper_encode(&asn_DEF_MeasurementRecordItem, r, b, err);
  return b;
}

Bytes enc_item(const MeasurementDataItem_t *it) {
  Bytes b;
  std::string err;
  aper_encode(&asn_DEF_MeasurementDataItem, it, b, err);
  return b;
}

// The m-eNB-UE-X2AP-ID of an en-gNB-UEID (= the IMSI with this test's contexts);
// any other UEID alternative gives UINT64_MAX, which matches no UE.
uint64_t x2ap_ue_id(const MatchingUEidItem_t *m) {
  if (m->ueID.present != UEID_PR_en_gNB_UEID) return UINT64_MAX;
  return (uint64_t)m->ueID.choice.en_gNB_UEID->m_eNB_UE_X2AP_ID;
}

// Format 2 message -> {(item, X2AP UE ID) -> per-metric record octets}.
using UeRecords = std::map<std::pair<int, uint64_t>, std::vector<Bytes>>;
bool ue_records(const Bytes &msg, UeRecords &out, int &items, unsigned long &granul) {
  E2SM_KPM_IndicationMessage_t *m = decode_msg(msg);
  if (!m || m->indicationMessage_formats.present !=
                E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format2) {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, m);
    return false;
  }
  auto *f2 = m->indicationMessage_formats.choice.indicationMessage_Format2;
  std::vector<uint64_t> imsis;
  auto *ul = f2->measCondUEidList.list.array[0]->matchingUEidList;
  for (int u = 0; u < ul->list.count; u++) imsis.push_back(x2ap_ue_id(ul->list.array[u]));
  size_t nUe = imsis.size(), nMet = (size_t)f2->measCondUEidList.list.count;
  items = f2->measData.list.count;
  granul = f2->granulPeriod ? *f2->granulPeriod : 0;
  for (int t = 0; t < items; t++) {
    auto &rec = f2->measData.list.array[t]->measRecord.list;
    if ((size_t)rec.count != nUe * nMet) break;
    for (size_t u = 0; u < nUe; u++)
      for (size_t k = 0; k < nMet; k++) out[{t, imsis[u]}].push_back(enc_record(rec.array[k * nUe + u]));
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, m);
  return true;
}

// The ueContext line for a sample: each of its UEs with lteRnti = imsi.
json ue_context_for(const json &sample) {
  json ues = json::array();
  for (const json &u : sample.value("ues", json::array()))
    ues.push_back({{"imsi", u["imsi"]}, {"lteRnti", u["imsi"]}, {"mnCellId", 1}, {"mmeUeS1apId", u["imsi"]}});
  return {{"type", "ueContext"}, {"v", 1}, {"nodeId", sample["nodeId"]}, {"seq", sample["seq"]}, {"ues", ues}};
}

// ---- the sample fixture ----
struct Fixture {
  HelloInfo hello;
  std::vector<SampleRecords> samples;
};

bool load_samples(const std::string &path, SampleEncoder &enc, Fixture &f) {
  std::ifstream in(path);
  std::string line, err;
  bool first = true;
  while (std::getline(in, line)) {
    json j = json::parse(line, nullptr, false);
    if (first) {
      first = false;
      if (!enc.accept_hello(j, f.hello, err)) return false;
      continue;
    }
    if (!enc.accept_ue_context(ue_context_for(j), err)) return false;
    SampleRecords r;
    if (!enc.build(j, r, err)) return false;
    f.samples.push_back(r);
  }
  return !f.samples.empty();
}

// Feeds seqs through a one-subscription table of P / T = perReport, then ends it
// (bye). Returns the reports (their seqs) and checks the sample accounting.
std::vector<std::vector<int64_t>> run_periods(const std::string &name, long perReport, const std::vector<int64_t> &seqs,
                                              bool reportsFail = false, uint64_t *gapsOut = nullptr) {
  SubscriptionTable t;
  Subscription s;
  s.requestorId = 1;
  s.samplesPerReport = perReport;
  t.add_or_replace(s);
  std::vector<std::vector<int64_t>> reports;
  size_t fwd = 0, gap = 0, failed = 0;
  uint64_t gaps = 0;
  for (int64_t q : seqs) {
    SampleRecords r;
    r.seq = q;
    PeriodTally k = t.add_sample(r, [&](Subscription &, const std::vector<SampleRecords> &w) {
      reports.emplace_back();
      for (const SampleRecords &x : w) reports.back().push_back(x.seq);
      return !reportsFail;
    });
    fwd += k.forwarded;
    gap += k.gapDiscarded;
    failed += k.failed;
    gaps += k.gaps;
  }
  if (gapsOut) *gapsOut = gaps;
  size_t unreported = t.end_periods();
  check(fwd + gap + failed + unreported == seqs.size() && t.pending_samples() == 0,
        name + ": samplesIn " + std::to_string(seqs.size()) + " == forwarded " + std::to_string(fwd) +
            " + gapDiscarded " + std::to_string(gap) + " + failed " + std::to_string(failed) + " + unreported at bye " +
            std::to_string(unreported));
  return reports;
}

std::string seqs_str(const std::vector<std::vector<int64_t>> &reports) {
  std::string out;
  for (const auto &r : reports) {
    out += "[";
    for (size_t i = 0; i < r.size(); i++) out += (i ? "," : "") + std::to_string(r[i]);
    out += "]";
  }
  return out;
}

void period_checks() {
  using R = std::vector<std::vector<int64_t>>;
  R r = run_periods("period-pt", 1, {5, 6, 7});
  check(r == R{{5}, {6}, {7}}, "period-pt: P = T reports every sample at once: " + seqs_str(r));
  r = run_periods("period-p3", 3, {10, 11, 12, 13, 14, 15, 16, 17});
  check(r == R{{10, 11, 12}, {13, 14, 15}}, "period-p3: aligned to the first sample (seq 10), 3 per report, "
                                             "16..17 cut by bye: " + seqs_str(r));
  uint64_t gaps = 0;
  r = run_periods("period-gap", 3, {1, 2, 4, 5, 6, 7}, false, &gaps);
  check(r == R{{4, 5, 6}} && gaps == 1, "period-gap: seq 3 missing restarts the period at 4: " + seqs_str(r) +
                                             ", reportGaps " + std::to_string(gaps));
  r = run_periods("period-gap-after-report", 3, {1, 2, 3, 5, 6, 7}, false, &gaps);
  check(r == R{{1, 2, 3}, {5, 6, 7}} && gaps == 1,
        "period-gap-after-report: a gap right after a completed period counts: " + seqs_str(r) + ", reportGaps " +
            std::to_string(gaps));
  {
    // After bye (end_periods) a new ns-3 run restarts its seqs: not a gap.
    SubscriptionTable t;
    Subscription s;
    s.samplesPerReport = 2;
    t.add_or_replace(s);
    auto ok = [](Subscription &, const std::vector<SampleRecords> &) { return true; };
    SampleRecords x;
    uint64_t g = 0;
    for (int64_t q : {7, 8, 9}) {
      x.seq = q;
      g += t.add_sample(x, ok).gaps;
    }
    size_t cut = t.end_periods();
    x.seq = 0;
    g += t.add_sample(x, ok).gaps;
    check(g == 0 && cut == 1, "period-bye-rerun: seqs restarting after bye are no gap");
  }
  r = run_periods("period-fail", 2, {1, 2, 3}, true);
  check(r == R{{1, 2}}, "period-fail: a report that is not sent still ends its period: " + seqs_str(r));

  // A replaced subscription starts a new period; the old period's samples are unreported.
  SubscriptionTable t;
  Subscription s;
  s.samplesPerReport = 3;
  t.add_or_replace(s);
  SampleRecords x;
  x.seq = 1;
  t.add_sample(x, [](Subscription &, const std::vector<SampleRecords> &) { return true; });
  size_t before = t.pending_samples();
  t.add_or_replace(s);
  check(before == 1 && t.pending_samples() == 0, "period-replace: a replaced subscription's period restarts");
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <metric-map.json> <fixtures-dir> <out-dir>\n", argv[0]);
    return 2;
  }
  std::string fx = argv[2], err;
  outDir = argv[3];
  MetricMap map;
  if (!load_metric_map(argv[1], "gnb", map, err)) return fprintf(stderr, "metric map: %s\n", err.c_str()), 1;
  Config cfg;  // the defaults the golden octets were made with
  cfg.nodeId = 2;
  cfg.kind = "gnb";
  plmn_to_bcd(cfg.plmn, cfg.plmnBcd);
  SampleEncoder enc(cfg, map);
  Fixture f;
  check(load_samples(fx + "/ipc-samples-gnb2-seq26-35.jsonl", enc, f) && f.samples.size() == 10,
        "fixture: hello accepted, 10 samples built");
  if (f.samples.size() != 10) return 1;

  // A repeated IMSI in one sample: the first entry is kept, the other counted.
  {
    json dup = json::parse(R"({"type":"sample","nodeId":2,"seq":1,"simTimeNs":100000000,"ues":[{"imsi":7},{"imsi":7},{"imsi":8}]})");
    json ctx = json::parse(R"({"type":"ueContext","v":1,"nodeId":2,"seq":1,"ues":[)"
                           R"({"imsi":7,"lteRnti":7,"mnCellId":1,"mmeUeS1apId":7},)"
                           R"({"imsi":8,"lteRnti":8,"mnCellId":1,"mmeUeS1apId":8}]})");
    const uint64_t before = stats().uesDroppedDuplicateImsi;
    SampleRecords r;
    bool ok = enc.accept_ue_context(ctx, err) && enc.build(dup, r, err);
    check(ok && r.ues.size() == 2 && r.ues[0].first == 7 && stats().uesDroppedDuplicateImsi == before + 1,
          "duplicate IMSI: kept once, uesDropped.duplicateImsi + 1");
  }

  // hello against E2_INDICATION_PERIOD_MS
  {
    HelloInfo h;
    json hello = {{"schema", "ns3-e2-ipc"}, {"v", 1}, {"nodeId", 2}, {"kind", "gnb"}, {"periodNs", 100000000},
                  {"simStartEpochMs", 0}};
    check(enc.accept_hello(hello, h, err), "hello periodNs 100 ms == E2_INDICATION_PERIOD_MS accepted");
    // The agent does not judge `minor`: minor 3 (ueContext) is accepted, and so
    // is an older minor, whose samples then fail loudly for want of a ueContext.
    hello["minor"] = 3;
    check(enc.accept_hello(hello, h, err), "hello minor 3 accepted");
    hello["minor"] = 2;
    check(enc.accept_hello(hello, h, err), "hello minor 2 accepted");
    hello["periodNs"] = 200000000;
    check(!enc.accept_hello(hello, h, err), "hello periodNs 200 ms != E2_INDICATION_PERIOD_MS rejected: " + err);
  }

  std::ofstream lines(outDir + "/ind-lines.txt");
  json expect = json::object();

  // (a) P = T: byte-identical to the pre-change encoder.
  auto golden = read_keyed(fx + "/kpm-tt-golden-gnb2-seq26-35.txt");
  std::vector<EncodedReport> tt;
  size_t pieces = 0, same = 0;
  for (const SampleRecords &r : f.samples) {
    EncodedReport rep;
    bool ok = enc.encode({r}, f.hello, rep, err);
    std::string s = std::to_string(r.seq);
    auto cmp = [&](const std::string &key, const Bytes &b) {
      pieces++;
      auto g = golden.find(s + " " + key);
      if (g != golden.end() && g->second == to_hex(b)) same++;
      else printf("  differs: seq %s %s\n", s.c_str(), key.c_str());
    };
    if (ok) {
      cmp("hdr", rep.header);
      cmp("cell", rep.cellMsg);
      for (size_t k = 0; k < rep.ueMsgs.size(); k++) cmp("ue" + std::to_string(k), rep.ueMsgs[k]);
      lines << "tt-" << s << "-cell " << to_hex(rep.header) << " " << to_hex(rep.cellMsg) << "\n";
      for (size_t k = 0; k < rep.ueMsgs.size(); k++)
        lines << "tt-" << s << "-ue" << k << " " << to_hex(rep.header) << " " << to_hex(rep.ueMsgs[k]) << "\n";
    }
    tt.push_back(rep);
  }
  check(pieces == golden.size() && same == golden.size(),
        "tt-byte-identical: " + std::to_string(same) + "/" + std::to_string(golden.size()) +
            " header/cell/UE octet strings equal the golden's");

  auto kp = read_keyed(fx + "/kpimon-subscription-octets.txt");
  Bytes trig100 = from_hex(kp["kpimon-trigger-100"]), trig1000 = from_hex(kp["kpimon-trigger-1000"]),
        trig150 = from_hex(kp["kpimon-trigger-150"]), trig10000 = from_hex(kp["kpimon-trigger-10000"]),
        g100 = from_hex(kp["kpimon-f3-byid-g100"]), g200 = from_hex(kp["kpimon-f3-byid-g200"]),
        byName = from_hex(kp["kpimon-f3-byname-g100"]), byNameWire = from_hex(kp["kpimon-f3-byname-wire"]),
        f1g100 = action_format1(100), junk = {0xff, 0xff};
  unsigned long v = 0;
  int fmt = 0;
  check(decode_kpm_reporting_period(trig100, v, err) && v == 100, "kpimon trigger 00 63 decodes to 100 ms");
  check(decode_kpm_reporting_period(trig10000, v, err) && v == 10000,
        "kpimon trigger encoded from 10000 ms == the old literal 08 27 0f: " + kp["kpimon-trigger-10000"]);
  check(decode_kpm_granularity(g100, v, fmt, err) && v == 100 && fmt == 3,
        "kpimon Format 3 by-ID definition (" + std::to_string(g100.size()) + " octets) decodes: G = 100 ms");
  check(decode_kpm_granularity(byName, v, fmt, err) && v == 100 && fmt == 3,
        "kpimon Format 3 by-name definition (" + std::to_string(byName.size()) + " octets) decodes: G = 100 ms");
  check(!decode_kpm_granularity(byNameWire, v, fmt, err),
        "the by-name definition as SubMgr put it on the wire does not decode: " + err);
  check(decode_kpm_granularity(f1g100, v, fmt, err) && v == 100 && fmt == 1, "Format 1 definition: G = 100 ms");

  // P = T = 100 (the gated configuration): admitted, one sample per report.
  {
    InboundPdu p;
    KpmAdmission a = admit("p100", subscription_request(1100, trig100, {{1, RICactionType_report, &g100}}), p);
    check(a.samplesPerReport == 1, "p100: P = T = 100 ms -> 1 sample per report");
    expect_response("p100", p, a, {1}, {});
  }

  // (b) P = 1000, G = 100.
  {
    InboundPdu p;
    KpmAdmission a = admit("p1000", subscription_request(1000, trig1000, {{1, RICactionType_report, &g100}}), p);
    check(a.samplesPerReport == 10, "p1000: P = 1000 ms, G = 100 ms -> 10 samples per report");
    expect_response("p1000", p, a, {1}, {});

    EncodedReport rep;
    bool ok = enc.encode(f.samples, f.hello, rep, err);
    check(ok, "p1000: report of seq 26..35 encoded " + err);
    check(rep.header == tt[0].header, "p1000: header colletStartTime = the first sample's (seq 26) header octets");
    E2SM_KPM_IndicationMessage_t *m = decode_msg(rep.cellMsg);
    bool f1 = m && m->indicationMessage_formats.present ==
                       E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;
    int items = f1 ? m->indicationMessage_formats.choice.indicationMessage_Format1->measData.list.count : 0;
    unsigned long gp = f1 && m->indicationMessage_formats.choice.indicationMessage_Format1->granulPeriod
                           ? *m->indicationMessage_formats.choice.indicationMessage_Format1->granulPeriod
                           : 0;
    check(f1 && items == 10 && gp == 100, "p1000: cell Format 1 with 10 measData items, granulPeriod 100 (" +
                                              std::to_string(rep.cellMsg.size()) + " octets)");
    int itemsEqual = 0;
    for (int t = 0; f1 && t < items && t < 10; t++) {
      E2SM_KPM_IndicationMessage_t *g = decode_msg(tt[t].cellMsg);
      if (g && enc_item(m->indicationMessage_formats.choice.indicationMessage_Format1->measData.list.array[t]) ==
                   enc_item(g->indicationMessage_formats.choice.indicationMessage_Format1->measData.list.array[0]))
        itemsEqual++;
      ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, g);
    }
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, m);
    check(itemsEqual == 10, "p1000: cell measData item t == the T/T message of seq 26+t, octet for octet (" +
                                std::to_string(itemsEqual) + "/10)");

    // UE: every (seq, UE) of the T/T messages, and noValue for a UE absent in a sample.
    UeRecords want, got;
    for (int t = 0; t < 10; t++)
      for (const Bytes &u : tt[t].ueMsgs) {
        UeRecords one;
        int n = 0;
        unsigned long g = 0;
        ue_records(u, one, n, g);
        for (auto &kv : one) want[{t, kv.first.second}] = kv.second;
      }
    bool shapes = !rep.ueMsgs.empty();
    for (const Bytes &u : rep.ueMsgs) {
      int n = 0;
      unsigned long g = 0;
      shapes = ue_records(u, got, n, g) && n == 10 && g == 100 && shapes;
    }
    check(shapes, "p1000: " + std::to_string(rep.ueMsgs.size()) +
                      " UE Format 2 message(s), each with 10 measData items, granulPeriod 100");
    MeasurementRecordItem_t nv{};
    nv.present = MeasurementRecordItem_PR_noValue;
    Bytes noValue = enc_record(&nv);
    size_t matched = 0, absent = 0, bad = 0;
    for (auto &kv : got) {
      auto w = want.find(kv.first);
      if (w != want.end()) (w->second == kv.second ? matched : bad)++;
      else {
        bool allNone = true;
        for (const Bytes &b : kv.second) allNone = allNone && b == noValue;
        (allNone ? absent : bad)++;
      }
    }
    check(bad == 0 && matched == want.size() && absent > 0,
          "p1000: UE records equal the T/T records for all " + std::to_string(matched) + " (seq, UE) pairs; " +
              std::to_string(absent) + " (seq, UE) pairs of a UE absent from that sample are noValue");
    lines << "p1000-cell " << to_hex(rep.header) << " " << to_hex(rep.cellMsg) << "\n";
    for (size_t k = 0; k < rep.ueMsgs.size(); k++)
      lines << "p1000-ue" << k << " " << to_hex(rep.header) << " " << to_hex(rep.ueMsgs[k]) << "\n";
    Bytes ind;
    check(build_indication(1000, 1, 2, 1, 0, rep.header, rep.cellMsg, ind, err), "p1000: cell RICindication built");
    write_hex("e2ap-p1000-indication-cell", ind);
    if (!rep.ueMsgs.empty() && build_indication(1000, 1, 2, 1, 1, rep.header, rep.ueMsgs[0], ind, err))
      write_hex("e2ap-p1000-indication-ue0", ind);
    expect["p1000"] = {{"ueMessages", rep.ueMsgs.size()}, {"pairsMatched", matched}, {"pairsAbsent", absent}};
  }

  // (c) P = 150: not a multiple of T.
  {
    InboundPdu p;
    KpmAdmission a = admit("p150", subscription_request(150, trig150, {{1, RICactionType_report, &g100}}), p);
    expect_failure("p150", p, a, CauseRICrequest_eventTriggerNotSupported);
  }
  {
    InboundPdu p;
    KpmAdmission a = admit("badtrigger", subscription_request(151, junk, {{1, RICactionType_report, &g100}}), p);
    expect_failure("badtrigger", p, a, CauseRICrequest_eventTriggerNotSupported);
  }

  // (d) G = 200 with P = 1000.
  {
    InboundPdu p;
    KpmAdmission a = admit("g200", subscription_request(200, trig1000, {{1, RICactionType_report, &g200}}), p);
    expect_failure("g200", p, a, CauseRICrequest_action_not_supported);
  }
  {
    InboundPdu p;
    KpmAdmission a = admit("mixed", subscription_request(201, trig1000, {{1, RICactionType_report, &g100},
                                                                          {2, RICactionType_report, &g200},
                                                                          {3, RICactionType_insert, &g100},
                                                                          {4, RICactionType_report, nullptr},
                                                                          {5, RICactionType_report, &byNameWire},
                                                                          {6, RICactionType_report, &f1g100}}),
                           p);
    const long ns = CauseRICrequest_action_not_supported;
    expect_response("mixed", p, a, {1, 6}, {{2, ns}, {3, ns}, {4, ns}, {5, ns}});
  }

  // K = P / T bound (E2_MAX_REPORT_RECORDS, default 20): checked at admission.
  {
    const long kMax = Config{}.maxReportRecords;
    InboundPdu p;
    KpmAdmission a = admit("k20", subscription_request(2000, event_trigger(2000), {{1, RICactionType_report, &g100}}), p);
    check(kMax == 20 && a.samplesPerReport == 20, "k20: P = 2000 ms -> K = 20 = E2_MAX_REPORT_RECORDS default, admitted");
    expect_response("k20", p, a, {1}, {});

    // Worst case for the sizes: every sample carries every UE of the fixture.
    size_t allUes = 0;
    for (const SampleRecords &r : f.samples) allUes = std::max(allUes, r.ues.size());
    std::vector<SampleRecords> full, worst;
    for (const SampleRecords &r : f.samples)
      if (r.ues.size() == allUes) full.push_back(r);
    for (size_t i = 0; i < 20; i++) {  // the full samples in turn, consecutive seqs
      worst.push_back(full[i % full.size()]);
      worst.back().seq = (int64_t)i + 1;
    }
    const uint64_t oversizeBefore = stats().uesDroppedOversize;
    EncodedReport rep;
    err.clear();
    bool ok = enc.encode(worst, f.hello, rep, err);
    size_t ues = 0, biggestUe = 0;
    for (const Bytes &u : rep.ueMsgs) {
      UeRecords one;
      int n = 0;
      unsigned long g = 0;
      ue_records(u, one, n, g);
      ues += one.size() / 20;
      biggestUe = std::max(biggestUe, u.size());
    }
    Bytes ind;
    check(ok && rep.cellMsg.size() <= (size_t)cfg.maxE2smBytes &&
              build_indication(2000, 1, 2, 1, 0, rep.header, rep.cellMsg, ind, err),
          "k20: worst-case cell Format 1, 20 items: " + std::to_string(rep.cellMsg.size()) +
              " octets <= E2_MAX_E2SM_BYTES=" + std::to_string(cfg.maxE2smBytes) + " " + err);
    check(ok && biggestUe <= (size_t)cfg.maxE2smBytes && ues == allUes && stats().uesDroppedOversize == oversizeBefore,
          "k20: worst-case UE Format 2, all " + std::to_string(allUes) + " UEs in every item, in " +
              std::to_string(rep.ueMsgs.size()) + " message(s), largest " + std::to_string(biggestUe) +
              " octets <= E2_MAX_E2SM_BYTES, none dropped as oversize");
    expect["k20"] = {{"cellOctets", rep.cellMsg.size()}, {"ueMessages", rep.ueMsgs.size()}, {"largestUeOctets", biggestUe}};
  }
  {
    InboundPdu p;
    KpmAdmission a = admit("k21", subscription_request(2100, event_trigger(2100), {{1, RICactionType_report, &g100}}), p);
    expect_failure("k21", p, a, CauseRICrequest_function_resource_limit);
  }
  {
    InboundPdu p;
    KpmAdmission a = admit("p10000", subscription_request(10000, trig10000, {{1, RICactionType_report, &g100}}), p);
    expect_failure("p10000", p, a, CauseRICrequest_function_resource_limit);
  }

  period_checks();

  std::ofstream(outDir + "/expect.json") << expect.dump(1) << "\n";
  print_stats_line(stats(), "test");  // the agent's stats line, with the counters this test moved
  if (failures) {
    printf("kpm-report-period-test: %d failure(s)\n", failures);
    return 1;
  }
  printf("kpm-report-period-test: ok\n");
  return 0;
}
