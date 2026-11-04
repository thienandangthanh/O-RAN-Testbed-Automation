// KPM UE ID part of the codec probe: feeds ueContext lines and samples through
// the agent's SampleEncoder for an en-gNB and for the eNB, decodes every UE
// message back with NIST's asn1c and checks the UEID CHOICE and its values
// (en-gNB-UEID: m-eNB-UE-X2AP-ID, globalENB-ID; eNB-UEID: MME UE S1AP ID,
// GUMMEI, m-eNB-UE-X2AP-ID), that the IMSI is never encoded as the UE ID (no gNB-UEID), and
// that a sample UE without a context is refused and counted.
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../src/agent-config.hpp"
#include "../src/agent-stats.hpp"
#include "../src/asn-util.hpp"
#include "../src/kpm-encoder.hpp"
#include "../src/metric-map.hpp"
#include "../src/sample-forwarder.hpp"

extern "C" {
#include "E2SM-COMMON-IEs_GlobalENB-ID.h"
#include "E2SM-KPM-IndicationMessage-Format2.h"
#include "E2SM-KPM-IndicationMessage.h"
#include "MatchingUEidItem.h"
#include "MatchingUEidList.h"
#include "MeasurementCondUEidItem.h"
#include "UEID-EN-GNB.h"
#include "UEID-ENB.h"
#include "UEID.h"
#include "xer_encoder.h"
}

using namespace agent;
using nlohmann::json;

namespace {

int failures = 0;

void check(bool ok, const std::string &what) {
  printf("  %s %s\n", ok ? "ok  " : "FAIL", what.c_str());
  if (!ok) failures++;
}

bool octets_eq(const OCTET_STRING_t &s, const Bytes &want) {
  return s.size == want.size() && Bytes(s.buf, s.buf + s.size) == want;
}

const Bytes kPlmn = {0x00, 0xF1, 0x10};

// The UE ID a Format 2 message must carry for one UE.
struct Want {
  long x2apId;
  unsigned long macroEnbId;   // en-gNB only
  unsigned long mmeUeS1apId;  // eNB only
};

bool engnb_matches(const UEID_EN_GNB_t *e, const Want &w) {
  const auto &g = e->globalENB_ID;
  const BIT_STRING_t &m = g.eNB_ID.choice.macro_eNB_ID;
  unsigned long macro = m.size == 3 ? ((unsigned long)m.buf[0] << 12 | (unsigned long)m.buf[1] << 4 | m.buf[2] >> 4) : ~0ul;
  return e->m_eNB_UE_X2AP_ID == w.x2apId && octets_eq(g.pLMNIdentity, kPlmn) &&
         g.eNB_ID.present == E2SM_COMMON_IEs_ENB_ID_PR_macro_eNB_ID && m.size == 3 && m.bits_unused == 4 &&
         macro == w.macroEnbId && !e->m_eNB_UE_X2AP_ID_Extension && !e->gNB_CU_UE_F1AP_ID &&
         !e->gNB_CU_CP_UE_E1AP_ID_List && !e->ran_UEID;
}

bool enb_matches(const UEID_ENB_t *e, const Want &w) {
  return e->mME_UE_S1AP_ID == w.mmeUeS1apId && octets_eq(e->gUMMEI.pLMN_Identity, kPlmn) &&
         octets_eq(e->gUMMEI.mME_Group_ID, {0x00, 0x01}) && octets_eq(e->gUMMEI.mME_Code, {0x01}) &&
         e->m_eNB_UE_X2AP_ID && *e->m_eNB_UE_X2AP_ID == w.x2apId && !e->m_eNB_UE_X2AP_ID_Extension &&
         !e->globalENB_ID;
}

// Decodes one Format 2 message and checks that every measCondUEid item lists
// exactly `want`, in order, as the CHOICE `choice`. Writes its XER to `xer`.
void check_ue_ids(const std::string &name, const Bytes &msg, UEID_PR choice, const std::vector<Want> &want,
                  size_t metrics, const std::string &xer) {
  void *p = nullptr;
  std::string err;
  bool ok = aper_decode_clean(&asn_DEF_E2SM_KPM_IndicationMessage, &p, msg.data(), msg.size(), err);
  check(ok, name + ": clean decode (" + std::to_string(msg.size()) + " octets) " + err);
  auto *m = (E2SM_KPM_IndicationMessage_t *)p;
  if (ok && m->indicationMessage_formats.present !=
                E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format2)
    ok = false;
  check(ok, name + ": Format 2");
  if (!ok) {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, p);
    return;
  }
  if (FILE *f = fopen(xer.c_str(), "w")) {
    xer_fprint(f, &asn_DEF_E2SM_KPM_IndicationMessage, p);
    fclose(f);
  }
  auto &items = m->indicationMessage_formats.choice.indicationMessage_Format2->measCondUEidList.list;
  bool lists = (size_t)items.count == metrics, rightChoice = true, values = true, noGnbUeId = true;
  for (int i = 0; i < items.count; i++) {
    const MatchingUEidList_t *l = items.array[i]->matchingUEidList;
    if (!l || (size_t)l->list.count != want.size()) {
      lists = false;
      continue;
    }
    for (int u = 0; u < l->list.count; u++) {
      const UEID_t &id = l->list.array[u]->ueID;
      if (id.present == UEID_PR_gNB_UEID) noGnbUeId = false;
      if (id.present != choice) {
        rightChoice = false;
        continue;
      }
      values = values && (choice == UEID_PR_en_gNB_UEID ? engnb_matches(id.choice.en_gNB_UEID, want[u])
                                                        : enb_matches(id.choice.eNB_UEID, want[u]));
    }
  }
  check(lists, name + ": one measCondUEid item per UE-list metric (" + std::to_string(metrics) + "), each with " +
                   std::to_string(want.size()) + " UE IDs");
  check(rightChoice, name + std::string(": UEID CHOICE ") +
                         (choice == UEID_PR_en_gNB_UEID ? "en-gNB-UEID" : "eNB-UEID") + " for every UE");
  check(noGnbUeId, name + ": no gNB-UEID");
  std::string desc;
  for (const Want &w : want)
    desc += (desc.empty() ? "" : "; ") +
            (choice == UEID_PR_en_gNB_UEID
                 ? "X2AP " + std::to_string(w.x2apId) + " globalENB {00F110, macro " + std::to_string(w.macroEnbId) + "}"
                 : "S1AP " + std::to_string(w.mmeUeS1apId) + " GUMMEI {00F110, 1, 1} X2AP " + std::to_string(w.x2apId));
  check(values, name + ": values " + desc + ", optional fields absent");
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, p);
}

json ue_context(int node, int64_t seq, const json &ues) {
  return {{"type", "ueContext"}, {"v", 1}, {"nodeId", node}, {"seq", seq}, {"ues", ues}};
}

json ctx(int64_t imsi, int64_t rnti, int64_t mnCell, int64_t s1ap) {
  return {{"imsi", imsi}, {"lteRnti", rnti}, {"mnCellId", mnCell}, {"mmeUeS1apId", s1ap}};
}

json sample(int node, int64_t seq, const std::vector<int64_t> &imsis) {
  json ues = json::array();
  for (int64_t i : imsis) ues.push_back({{"imsi", i}});
  return {{"type", "sample"}, {"v", 1}, {"nodeId", node}, {"seq", seq}, {"simTimeNs", seq * 100000000},
          {"ipcDropped", 0}, {"cell", json::object()}, {"ues", ues}};
}

// A sample with a UE outside the context set: not built, samplesNoUeContext + 1.
void check_refused(SampleEncoder &enc, const json &s, const std::string &what) {
  const uint64_t before = stats().samplesNoUeContext;
  SampleRecords r;
  std::string why;
  bool refused = !enc.build(s, r, why) && stats().samplesNoUeContext == before + 1;
  check(refused, what + ": sample not encoded, samplesNoUeContext + 1 (" + why + ")");
}

// A valid ueContext line: accepted, ipc.ueContext + 1.
void check_accepted(SampleEncoder &enc, const json &line, const std::string &what) {
  const uint64_t before = stats().ueContextRx;
  std::string why;
  bool ok = enc.accept_ue_context(line, why) && stats().ueContextRx == before + 1;
  check(ok, what + ": ueContext accepted" + (why.empty() ? "" : " (" + why + ")"));
}

// An invalid ueContext line: rejected, ipc.ueContextRejected + 1.
void check_rejected(SampleEncoder &enc, const json &line, const std::string &what) {
  const uint64_t before = stats().ueContextRejected;
  std::string why;
  bool rejected = !enc.accept_ue_context(line, why) && stats().ueContextRejected == before + 1;
  check(rejected, what + ": ueContext rejected, ipc.ueContextRejected + 1 (" + why + ")");
}

// Builds `samples` and encodes them as one report; false (and FAIL) unless it
// yields exactly one UE message.
bool encode_one(SampleEncoder &enc, const HelloInfo &hello, const std::vector<json> &samples, EncodedReport &rep,
                const std::string &what) {
  std::vector<SampleRecords> recs;
  std::string why;
  for (const json &s : samples) {
    SampleRecords r;
    if (!enc.build(s, r, why)) {
      check(false, what + ": sample built (" + why + ")");
      return false;
    }
    recs.push_back(r);
  }
  bool ok = enc.encode(recs, hello, rep, why) && rep.ueMsgs.size() == 1;
  check(ok, what + ": report encoded with one UE message" + (why.empty() ? "" : " (" + why + ")"));
  return ok;
}

// encode_format2 with one UE ID: must be refused.
void check_format2_refuses(const KpmUeId &id, const std::vector<MetricRow> &rows, const std::array<uint8_t, 3> &plmn,
                           const std::string &what) {
  std::vector<std::vector<std::vector<MeasValue>>> periods = {{{MeasValue{}}}};
  Bytes out;
  std::string why;
  bool refused = !encode_format2(periods, {id}, rows, plmn, true, 100, out, why);
  check(refused, "format2 refuses " + what + " (" + why + ")");
}

}  // namespace

int probe_kpm_ue_ids(const std::string &dir, const std::string &mapPath, const Bytes &hdr) {
  printf("kpm ue ids:\n");
  std::string err;
  std::ofstream lines(dir + "/ind-lines.txt", std::ios::app);
  HelloInfo hello;
  hello.periodNs = 100000000;
  hello.simStartEpochMs = 1792627200000LL;

  // en-gNB 2, master eNB 1.
  Config gnb;
  gnb.nodeId = 2;
  gnb.kind = "gnb";
  plmn_to_bcd(gnb.plmn, gnb.plmnBcd);
  MetricMap gmap;
  if (!load_metric_map(mapPath, "gnb", gmap, err)) return printf("  FAIL metric map gnb: %s\n", err.c_str()), 1;
  {
    SampleEncoder enc(gnb, gmap);
    check_refused(enc, sample(2, 1, {1}), "gNB, no ueContext yet");
    check_accepted(enc, ue_context(2, 2, json::array({ctx(1, 3, 1, 1), ctx(5, 4095, 1, 5)})),
                   "gNB {imsi 1: RNTI 3, imsi 5: RNTI 4095}");
    EncodedReport rep;
    if (encode_one(enc, hello, {sample(2, 2, {1, 5})}, rep, "gNB seq 2")) {
      check_ue_ids("gNB seq 2", rep.ueMsgs[0], UEID_PR_en_gNB_UEID, {{3, 1, 0}, {4095, 1, 0}}, gmap.ue.size(),
                   dir + "/f2-en-gnb-ueid.xer");
      lines << "f2engnb " << to_hex(hdr) << " " << to_hex(rep.ueMsgs[0]) << "\n";
    }
    check_refused(enc, sample(2, 3, {1, 9}), "gNB, imsi 9 without context");

    // A later line replaces the whole set: imsi 5 leaves, imsi 7 attaches.
    check_accepted(enc, ue_context(2, 4, json::array({ctx(1, 3, 1, 1), ctx(7, 4094, 1, 7)})), "gNB set {1, 7}");
    check_refused(enc, sample(2, 4, {1, 5}), "gNB, imsi 5 after it left the set");

    // A report over two samples keeps the UE ID a UE had in the newest of its
    // samples that carried it, also once the UE has left the current set.
    check_accepted(enc, ue_context(2, 5, json::array({ctx(1, 3, 1, 1), ctx(5, 4095, 1, 5)})), "gNB set {1, 5}");
    SampleRecords r5, r6;
    bool b5 = enc.build(sample(2, 5, {1, 5}), r5, err);
    check_accepted(enc, ue_context(2, 6, json::array({ctx(1, 3, 1, 1)})), "gNB set {1}");
    bool b6 = enc.build(sample(2, 6, {1}), r6, err);
    EncodedReport two;
    bool ok2 = b5 && b6 && enc.encode({r5, r6}, hello, two, err) && two.ueMsgs.size() == 1;
    check(ok2, "gNB report over seq 5..6 (imsi 5 left after seq 5) encoded" + (ok2 ? "" : " (" + err + ")"));
    if (ok2)
      check_ue_ids("gNB seq 5..6", two.ueMsgs[0], UEID_PR_en_gNB_UEID, {{3, 1, 0}, {4095, 1, 0}}, gmap.ue.size(),
                   dir + "/f2-en-gnb-ueid-two-samples.xer");

    // Invalid lines are rejected and clear the set, so the next sample fails loudly.
    check_rejected(enc, ue_context(2, 7, json::array({ctx(1, 4096, 1, 1)})),
                   "gNB lteRnti 4096 (above m-eNB-UE-X2AP-ID 0..4095)");
    check_refused(enc, sample(2, 7, {1}), "gNB, after a rejected ueContext");
    check_rejected(enc, ue_context(2, 8, json::array({ctx(1, 3, 1 << 20, 1)})),
                   "gNB mnCellId 2^20 (above the 20-bit macro eNB ID)");
    check_rejected(enc, ue_context(2, 8, json::array({ctx(1, 3, 1, 1), ctx(1, 4, 1, 1)})), "gNB imsi 1 repeated");
    check_rejected(enc, ue_context(3, 8, json::array({ctx(1, 3, 1, 1)})), "gNB line of another nodeId");
    check_rejected(enc, ue_context(2, 8, json::array({{{"imsi", 1}, {"lteRnti", 3}, {"mnCellId", 1}}})),
                   "gNB UE without mmeUeS1apId");
    check_rejected(enc, ue_context(2, 8, json::array({ctx(1, -1, 1, 1)})), "gNB negative lteRnti");
    check_accepted(enc, ue_context(2, 9, json::array()), "gNB set {}");
    SampleRecords cellOnly;
    std::string why;
    bool cellOk = enc.build(sample(2, 9, {}), cellOnly, why);
    check(cellOk, "gNB sample without UEs needs no context" + (why.empty() ? "" : " (" + why + ")"));
    // A new run (hello) forgets the contexts.
    check_accepted(enc, ue_context(2, 10, json::array({ctx(1, 3, 1, 1)})), "gNB set {1}");
    enc.reset_ue_contexts();
    check_refused(enc, sample(2, 10, {1}), "gNB, after the contexts were reset");
  }

  // eNB 1 (master of every en-gNB).
  Config enb = gnb;
  enb.nodeId = 1;
  enb.kind = "enb";
  MetricMap emap;
  if (!load_metric_map(mapPath, "enb", emap, err)) return printf("  FAIL metric map enb: %s\n", err.c_str()), 1;
  {
    SampleEncoder enc(enb, emap);
    check_accepted(enc, ue_context(1, 2, json::array({ctx(3, 2, 1, 3), ctx(4, 0, 1, 4294967295LL)})),
                   "eNB {imsi 3: RNTI 2, S1AP 3; imsi 4: RNTI 0, S1AP 2^32-1}");
    EncodedReport rep;
    if (encode_one(enc, hello, {sample(1, 2, {3, 4})}, rep, "eNB seq 2")) {
      check_ue_ids("eNB seq 2", rep.ueMsgs[0], UEID_PR_eNB_UEID, {{2, 0, 3}, {0, 0, 4294967295ul}}, emap.ue.size(),
                   dir + "/f2-enb-ueid.xer");
      lines << "f2enb " << to_hex(hdr) << " " << to_hex(rep.ueMsgs[0]) << "\n";
    }
    check_refused(enc, sample(1, 3, {3, 6}), "eNB, imsi 6 without context");
    check_rejected(enc, ue_context(1, 4, json::array({ctx(3, 2, 1, 4294967296LL)})), "eNB mmeUeS1apId 2^32");
  }

  // The encoder itself refuses IDs outside their ASN.1 ranges.
  {
    std::vector<MetricRow> one(gmap.ue.begin(), gmap.ue.begin() + 1);
    KpmUeId big;
    big.mEnbUeX2apId = 4096;
    big.macroEnbId = 1;
    check_format2_refuses(big, one, gnb.plmnBcd, "an en-gNB-UEID m-eNB-UE-X2AP-ID 4096");
    KpmUeId wide;
    wide.macroEnbId = 1u << 20;
    check_format2_refuses(wide, one, gnb.plmnBcd, "a 21-bit macro eNB ID");
    KpmUeId enbBig;
    enbBig.choice = KpmUeId::Choice::Enb;
    enbBig.mEnbUeX2apId = 4096;
    check_format2_refuses(enbBig, one, gnb.plmnBcd, "an eNB-UEID m-eNB-UE-X2AP-ID 4096");
  }

  printf("kpm ue id failures: %d\n", failures);
  return failures ? 1 : 0;
}
