// E2AP part of the codec probe: builds every outbound PDU the agent sends,
// round-trips it through a clean APER decode with NIST's asn1c, writes the
// hex (for text2pcap + tshark) and XER, and checks the post-edited fields.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

#include "../src/agent-config.hpp"
#include "../src/asn-util.hpp"
#include "../src/e2ap-builders.hpp"

extern "C" {
#include "E2AP-PDU.h"
#include "GlobalE2node-gNB-ID.h"
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

}  // namespace

int probe_e2ap(const std::string &dir, const Bytes &def) {
  Config cfg;
  cfg.nodeId = 2;
  cfg.kind = "gnb";
  cfg.gnbId = 2;
  plmn_to_bcd(cfg.plmn, cfg.plmnBcd);
  std::string err;
  Bytes b;
  printf("e2ap:\n");

  check(build_setup_request(cfg, def, b, err), ("build E2SetupRequest " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "setup-request", b)) {
    auto &l = p->choice.initiatingMessage->value.choice.E2setupRequest.protocolIEs.list;
    for (int i = 0; i < l.count; i++) {
      if (l.array[i]->value.present == E2setupRequestIEs__value_PR_GlobalE2node_ID) {
        GlobalgNB_ID_t &g = l.array[i]->value.choice.GlobalE2node_ID.choice.gNB->global_gNB_ID;
        const uint8_t plmn[3] = {0x00, 0xF1, 0x10}, gnb[4] = {0x00, 0x00, 0x00, 0x10};
        check(g.plmn_id.size == 3 && !memcmp(g.plmn_id.buf, plmn, 3), "setup: PLMN 00 F1 10");
        BIT_STRING_t &id = g.gnb_id.choice.gnb_ID;
        check(id.size == 4 && id.bits_unused == 3 && !memcmp(id.buf, gnb, 4), "setup: gNB-ID 2 (29 bits)");
      }
      if (l.array[i]->value.present == E2setupRequestIEs__value_PR_RANfunctions_List) {
        auto *it = (RANfunction_ItemIEs_t *)l.array[i]->value.choice.RANfunctions_List.list.array[0];
        RANfunction_Item_t &f = it->value.choice.RANfunction_Item;
        check(f.ranFunctionID == 2 && f.ranFunctionRevision == 2, "setup: RAN function 2, revision 2");
        check(std::string((char *)f.ranFunctionOID.buf, f.ranFunctionOID.size) == cfg.kpmOid, "setup: KPM v3 OID");
        check(f.ranFunctionDefinition.size == def.size() && !memcmp(f.ranFunctionDefinition.buf, def.data(), def.size()),
              "setup: definition bytes");
      }
    }
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  }

  check(build_subscription_response(1234, 7, 2, {1, 3}, b, err), ("build RICsubscriptionResponse " + err).c_str());
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

  check(build_service_update(cfg, def, 5, b, err), ("build RICserviceUpdate " + err).c_str());
  if (E2AP_PDU_t *p = roundtrip(dir, "service-update", b)) {
    auto &l = p->choice.initiatingMessage->value.choice.RICserviceUpdate.protocolIEs.list;
    check(l.count == 2 && l.array[0]->id == ProtocolIE_ID_id_TransactionID &&
              l.array[0]->value.choice.TransactionID == 5,
          "service update: TransactionID 5 first");
    check(l.count == 2 && l.array[1]->id == ProtocolIE_ID_id_RANfunctionsModified &&
              l.array[1]->value.present == RICserviceUpdate_IEs__value_PR_RANfunctions_List_1,
          "service update: RANfunctionsModified decodes as the Modified alternative");
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
