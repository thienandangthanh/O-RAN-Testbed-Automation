// E2AP part of the codec probe: builds every outbound PDU the agent sends,
// round-trips it through a clean APER decode with NIST's asn1c, writes the
// hex (for text2pcap + tshark) and XER, and checks the post-edited fields.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

#include "../src/agent-config.hpp"
#include "../src/asn-util.hpp"
#include "../src/e2-setup-request.hpp"
#include "../src/e2ap-builders.hpp"
#include "x2ap-codec.h"

extern "C" {
#include "E2AP-PDU.h"
#include "E2AP-IEs_GlobalENB-ID.h"
#include "E2AP-IEs_GlobalenGNB-ID.h"
#include "E2nodeComponentInterfaceX2.h"
#include "GlobalE2node-eNB-ID.h"
#include "GlobalE2node-en-gNB-ID.h"
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "SuccessfulOutcome.h"
#include "xer_encoder.h"
}

using namespace agent;

namespace {

int failures = 0;

void check(bool ok, const char *what) {
  printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
  if (!ok) failures++;
}

// Writes hex + XER, returns the decoded PDU (caller frees) or nullptr.
E2AP_PDU_t *roundtrip(const std::string &dir, const char *name, const Bytes &b) {
  std::ofstream(dir + "/e2ap-" + name + ".hex") << to_hex(b) << "\n";
  void *p = nullptr;
  std::string err;
  bool ok = aper_decode_clean(&asn_DEF_E2AP_PDU, &p, b.data(), b.size(), err);
  check(ok, (std::string(name) + ": clean decode (" + std::to_string(b.size()) + " octets) " + err).c_str());
  if (!ok) {
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
    return nullptr;
  }
  FILE *f = fopen((dir + "/e2ap-" + name + ".xer").c_str(), "w");
  if (f) {
    xer_fprint(f, &asn_DEF_E2AP_PDU, p);
    fclose(f);
  }
  return (E2AP_PDU_t *)p;
}


// The X2 component parts of gNB 2 (neighbour eNB 1) and of eNB 1 (neighbours en-gNB 2 and 3) with the R-3
// constants, encoded by the independent codec (pycrate 0.8.1, tools/asn1-indep e2indep/x2ap.py:
// endc_x2_setup_{request,response}_{en_gnb,enb}, served_nr_cell(scs="scs60", nrb="nrb24", configured_tac=00 01),
// served_eutra_cell(bw100), measurement_timing_configuration(633333)).
const char *kReqEnGnb2 = "0024004100000100f4003a40000200fc00090000f110500000000200fd002600000400020000f1100000000210001000f110410009a9f500004d004100071011353ea50000";
const char *kRspEnb1 = "2024003100000100f6002a000002001500080000f1100000001000fa0017000000010000f11000001010001000f1100046b4006455";
const char *kReqEnb1 = "0024003100000100f4002a000002001500080000f1100000001000fa0017000000010000f11000001010001000f1100046b4006455";
const char *kRspEnGnb[2] = {
    "2024004100000100f6003a40000200fc00090000f110500000000200fd002600000400020000f1100000000210001000f110410009a9f500004d004100071011353ea50000",
    "2024004100000100f6003a40000200fc00090000f110500000000300fd002600000400030000f1100000000310001000f110410009a9f500004d004100071011353ea50000"};

std::string hex_of(const OCTET_STRING_t &o) { return to_hex(Bytes(o.buf, o.buf + o.size)); }

// Checks the decoded E2SetupRequest of one node: Global E2 Node ID, RAN functions, X2 components.
void check_setup(const char *who, E2AP_PDU_t *p, const Config &cfg, const std::vector<RanFunctionSpec> &funcs,
                 const std::vector<std::pair<std::string, std::string>> &parts) {
  auto &l = p->choice.initiatingMessage->value.choice.E2setupRequest.protocolIEs.list;
  std::string w = std::string(who) + ": ";
  check(l.count == 4 && l.array[0]->id == ProtocolIE_ID_id_TransactionID, (w + "4 IEs, TransactionID first").c_str());
  const uint8_t plmn[3] = {0x00, 0xF1, 0x10};
  for (int i = 0; i < l.count; i++) {
    auto &v = l.array[i]->value;
    check(l.array[i]->criticality == Criticality_reject, (w + "IE criticality reject").c_str());
    if (v.present == E2setupRequestIEs__value_PR_GlobalE2node_ID && cfg.kind == "gnb") {
      bool ok = v.choice.GlobalE2node_ID.present == GlobalE2node_ID_PR_en_gNB;
      if (ok) {
        auto &g = v.choice.GlobalE2node_ID.choice.en_gNB->global_en_gNB_ID;
        const uint8_t id[4] = {0x00, 0x00, 0x00, 0x02};
        ok = g.pLMN_Identity.size == 3 && !memcmp(g.pLMN_Identity.buf, plmn, 3) && g.gNB_ID.choice.gNB_ID.size == 4 &&
             g.gNB_ID.choice.gNB_ID.bits_unused == 0 && !memcmp(g.gNB_ID.choice.gNB_ID.buf, id, 4);
      }
      check(ok, (w + "Global en-gNB ID: PLMN 00F110, gNB ID 00000002 (32 bits)").c_str());
    }
    if (v.present == E2setupRequestIEs__value_PR_GlobalE2node_ID && cfg.kind == "enb") {
      bool ok = v.choice.GlobalE2node_ID.present == GlobalE2node_ID_PR_eNB;
      if (ok) {
        auto &g = v.choice.GlobalE2node_ID.choice.eNB->global_eNB_ID;
        const uint8_t id[3] = {0x00, 0x00, 0x10};
        ok = g.pLMN_Identity.size == 3 && !memcmp(g.pLMN_Identity.buf, plmn, 3) &&
             g.eNB_ID.present == E2AP_IEs_ENB_ID_PR_macro_eNB_ID && g.eNB_ID.choice.macro_eNB_ID.size == 3 &&
             g.eNB_ID.choice.macro_eNB_ID.bits_unused == 4 && !memcmp(g.eNB_ID.choice.macro_eNB_ID.buf, id, 3);
      }
      check(ok, (w + "Global eNB ID: PLMN 00F110, macro eNB ID 00001 (20 bits)").c_str());
    }
    if (v.present == E2setupRequestIEs__value_PR_RANfunctions_List) {
      auto &fl = v.choice.RANfunctions_List.list;
      bool ok = fl.count == (int)funcs.size();
      for (int k = 0; ok && k < fl.count; k++) {
        auto *it = (RANfunction_ItemIEs_t *)fl.array[k];
        RANfunction_Item_t &f = it->value.choice.RANfunction_Item;
        ok = it->criticality == Criticality_ignore && f.ranFunctionID == funcs[k].id &&
             f.ranFunctionRevision == funcs[k].revision &&
             std::string((char *)f.ranFunctionOID.buf, f.ranFunctionOID.size) == funcs[k].oid &&
             Bytes(f.ranFunctionDefinition.buf, f.ranFunctionDefinition.buf + f.ranFunctionDefinition.size) ==
                 funcs[k].definition;
      }
      check(ok, (w + "RAN functions " + (cfg.kind == "gnb" ? "{2 KPM, 3 RC}" : "{2 KPM}") +
                 ", item criticality ignore, definitions as given").c_str());
    }
    if (v.present == E2setupRequestIEs__value_PR_E2nodeComponentConfigAddition_List) {
      auto &cl = v.choice.E2nodeComponentConfigAddition_List.list;
      bool ok = cl.count == (int)parts.size();
      for (int k = 0; ok && k < cl.count; k++) {
        auto &c = ((E2nodeComponentConfigAddition_ItemIEs_t *)cl.array[k])->value.choice.E2nodeComponentConfigAddition_Item;
        auto *x2 = c.e2nodeComponentID.present == E2nodeComponentID_PR_e2nodeComponentInterfaceTypeX2
                       ? c.e2nodeComponentID.choice.e2nodeComponentInterfaceTypeX2
                       : nullptr;
        ok = c.e2nodeComponentInterfaceType == E2nodeComponentInterfaceType_x2 && x2 &&
             (cfg.kind == "gnb" ? x2->global_eNB_ID && !x2->global_en_gNB_ID
                                : x2->global_en_gNB_ID && !x2->global_eNB_ID) &&
             hex_of(c.e2nodeComponentConfiguration.e2nodeComponentRequestPart) == parts[k].first &&
             hex_of(c.e2nodeComponentConfiguration.e2nodeComponentResponsePart) == parts[k].second;
        x2c_setup_summary sq, sr;
        auto &rq = c.e2nodeComponentConfiguration.e2nodeComponentRequestPart;
        auto &rs = c.e2nodeComponentConfiguration.e2nodeComponentResponsePart;
        ok = ok && x2c_decode_endc_setup(rq.buf, rq.size, &sq, nullptr, 0) == 0 &&
             x2c_decode_endc_setup(rs.buf, rs.size, &sr, nullptr, 0) == 0 && !sq.response && sr.response &&
             sq.en_gnb == (cfg.kind == "gnb") && sr.en_gnb == (cfg.kind != "gnb");
      }
      check(ok, (w + "X2 components (one per neighbour): interface x2, neighbour ID, request = own ENDCX2SetupRequest, "
                     "response = neighbour's ENDCX2SetupResponse, byte-equal to pycrate").c_str());
    }
  }
}

}  // namespace

int probe_e2ap(const std::string &dir, const Bytes &def) {
  Config cfg;
  cfg.nodeId = 2;
  cfg.kind = "gnb";
  cfg.gnbId = 2;
  cfg.x2Peers = {1};
  plmn_to_bcd(cfg.plmn, cfg.plmnBcd);
  std::string err;
  Bytes b;
  printf("e2ap:\n");

  std::vector<RanFunctionSpec> funcs;
  check(node_ran_functions(cfg, def, funcs, err) && funcs.size() == 2 && funcs[1].id == 3 &&
            funcs[1].oid == "1.3.6.1.4.1.53148.1.1.2.3",
        ("gNB RAN functions 2 and 3 (E2SM-RC OID) " + err).c_str());
  check(build_setup_request(cfg, funcs, 1, b, err), ("build E2SetupRequest gNB 2 " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "setup-request", b)) {
    check_setup("setup gNB 2", p, cfg, funcs, {{kReqEnGnb2, kRspEnb1}});
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  }
  Config enb = cfg;
  enb.nodeId = 1;
  enb.kind = "enb";
  enb.x2Peers = {2, 3};
  std::vector<RanFunctionSpec> efuncs;
  check(node_ran_functions(enb, def, efuncs, err) && efuncs.size() == 1, ("eNB RAN function 2 only " + err).c_str());
  check(build_setup_request(enb, efuncs, 1, b, err), ("build E2SetupRequest eNB 1 " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "setup-request-enb", b)) {
    check_setup("setup eNB 1", p, enb, efuncs, {{kReqEnb1, kRspEnGnb[0]}, {kReqEnb1, kRspEnGnb[1]}});
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  }
  Config farCell = cfg;
  farCell.nodeId = 1008;
  check(!build_setup_request(farCell, funcs, 1, b, err), "setup: cellId 1008 (outside the NR PCI range) refused");

  check(build_subscription_response(1234, 7, 2, {1, 3}, {}, b, err), ("build RICsubscriptionResponse " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "subscription-response", b)) {
    auto &l = p->choice.successfulOutcome->value.choice.RICsubscriptionResponse.protocolIEs.list;
    bool fn = false, acts = false;
    for (int i = 0; i < l.count; i++) {
      if (l.array[i]->value.present == RICsubscriptionResponse_IEs__value_PR_RANfunctionID)
        fn = l.array[i]->value.choice.RANfunctionID == 2;
      if (l.array[i]->value.present == RICsubscriptionResponse_IEs__value_PR_RICaction_Admitted_List)
        acts = l.array[i]->value.choice.RICaction_Admitted_List.list.count == 2;
    }
    check(fn, "subscription response: RANfunctionID 2 (not 147)");
    check(acts && l.count == 3, "subscription response: 2 admitted actions, no not-admitted IE");
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  }

  check(build_subscription_delete_response(1234, 7, 2, b, err), ("build RICsubscriptionDeleteResponse " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "subscription-delete-response", b)) {
    check(p->choice.successfulOutcome->procedureCode == ProcedureCode_id_RICsubscriptionDelete,
          "delete response: procedure 9");
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  }

  check(build_service_update(funcs, 5, b, err), ("build RICserviceUpdate " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "service-update", b)) {
    auto &l = p->choice.initiatingMessage->value.choice.RICserviceUpdate.protocolIEs.list;
    check(l.count == 2 && l.array[0]->id == ProtocolIE_ID_id_TransactionID &&
              l.array[0]->value.choice.TransactionID == 5,
          "service update: TransactionID 5 first");
    check(l.count == 2 && l.array[1]->id == ProtocolIE_ID_id_RANfunctionsModified &&
              l.array[1]->value.present == RICserviceUpdate_IEs__value_PR_RANfunctions_List_1,
          "service update: RANfunctionsModified decodes as the Modified alternative");
    check(l.count == 2 && l.array[1]->value.choice.RANfunctions_List_1.list.count == 2,
          "service update: both RAN functions of the gNB");
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  }

  Bytes hdr(9, 0x01), msg(7000, 0x02);
  check(build_indication(1234, 7, 2, 1, 65535, hdr, msg, b, err), ("build RICindication 7000 " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "indication", b)) ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  Bytes big(8193, 0x02);
  check(!build_indication(1234, 7, 2, 1, 1, hdr, big, b, err), "indication: 8193-octet message refused");

  printf("e2ap failures: %d\n", failures);
  return failures ? 1 : 0;
}
