// E2SetupRequest builder (see e2-setup-request.hpp). The PDU is built from calloc'd asn1c structures and released
// with one ASN_STRUCT_FREE.
#include "e2-setup-request.hpp"

#include <cstdlib>

#include "e2-node-identity.hpp"
#include "rc-codec.h"
#include "rc-control.hpp"

extern "C" {
#include "E2AP-PDU.h"
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
}

namespace agent {

namespace {

template <typename T>
T *add_to(void *list) {
  T *p = (T *)calloc(1, sizeof(T));
  if (p && ASN_SEQUENCE_ADD(list, p) != 0) {
    free(p);
    return nullptr;
  }
  return p;
}

E2setupRequestIEs_t *add_ie(E2setupRequest_t &m, long id, E2setupRequestIEs__value_PR present) {
  auto *ie = add_to<E2setupRequestIEs_t>(&m.protocolIEs.list);
  if (ie) {
    ie->id = id;
    ie->criticality = Criticality_reject;
    ie->value.present = present;
  }
  return ie;
}

}  // namespace

bool fill_ran_functions_list(RANfunctions_List_t &l, const std::vector<RanFunctionSpec> &funcs) {
  for (const auto &f : funcs) {
    auto *it = add_to<RANfunction_ItemIEs_t>(&l.list);
    if (!it) return false;
    it->id = ProtocolIE_ID_id_RANfunction_Item;
    it->criticality = Criticality_ignore;
    it->value.present = RANfunction_ItemIEs__value_PR_RANfunction_Item;
    RANfunction_Item_t &r = it->value.choice.RANfunction_Item;
    r.ranFunctionID = f.id;
    r.ranFunctionRevision = f.revision;
    if (OCTET_STRING_fromBuf(&r.ranFunctionDefinition, (const char *)f.definition.data(), (int)f.definition.size()) !=
            0 ||
        !set_octets(&r.ranFunctionOID, f.oid))
      return false;
  }
  return !funcs.empty();
}

namespace {

bool add_x2_components(E2nodeComponentConfigAddition_List_t &l, const Config &cfg, std::string &err) {
  std::vector<X2Component> comps;
  if (!build_x2_components(cfg, comps, err)) return false;
  for (const auto &c : comps) {
    auto *it = add_to<E2nodeComponentConfigAddition_ItemIEs_t>(&l.list);
    if (!it) return false;
    it->id = ProtocolIE_ID_id_E2nodeComponentConfigAddition_Item;
    it->criticality = Criticality_reject;
    it->value.present = E2nodeComponentConfigAddition_ItemIEs__value_PR_E2nodeComponentConfigAddition_Item;
    E2nodeComponentConfigAddition_Item_t &a = it->value.choice.E2nodeComponentConfigAddition_Item;
    a.e2nodeComponentInterfaceType = E2nodeComponentInterfaceType_x2;
    E2nodeComponentConfiguration_t &conf = a.e2nodeComponentConfiguration;
    if (!fill_x2_component_id(cfg, c, a.e2nodeComponentID, err) ||
        OCTET_STRING_fromBuf(&conf.e2nodeComponentRequestPart, (const char *)c.requestPart.data(),
                             (int)c.requestPart.size()) != 0 ||
        OCTET_STRING_fromBuf(&conf.e2nodeComponentResponsePart, (const char *)c.responsePart.data(),
                             (int)c.responsePart.size()) != 0)
      return false;
  }
  return true;
}

}  // namespace

bool node_ran_functions(const Config &cfg, const Bytes &kpmDefinition, std::vector<RanFunctionSpec> &out,
                        std::string &err) {
  out.clear();
  out.push_back({cfg.ranFuncId, kRanFunctionRevision, cfg.kpmOid, kpmDefinition});
  if (cfg.kind != "gnb") return true;
  uint8_t buf[1024];
  long n = rcc_encode_ran_function_definition(buf, sizeof buf);
  if (n <= 0) {
    err = "E2SM-RC RAN Function Definition: encoding failed";
    return false;
  }
  out.push_back({kRcRanFunctionId, kRcRanFunctionRevision, rcc_ran_function_oid(), Bytes(buf, buf + n)});
  return true;
}

bool build_setup_request(const Config &cfg, const std::vector<RanFunctionSpec> &funcs, long transactionId, Bytes &out,
                         std::string &err) {
  auto *pdu = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
  auto *im = pdu ? (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t)) : nullptr;
  bool ok = im != nullptr;
  if (ok) {
    pdu->present = E2AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = im;
    im->procedureCode = ProcedureCode_id_E2setup;
    im->criticality = Criticality_reject;
    im->value.present = InitiatingMessage__value_PR_E2setupRequest;
    E2setupRequest_t &m = im->value.choice.E2setupRequest;
    E2setupRequestIEs_t *tx = add_ie(m, ProtocolIE_ID_id_TransactionID, E2setupRequestIEs__value_PR_TransactionID);
    E2setupRequestIEs_t *gid = add_ie(m, ProtocolIE_ID_id_GlobalE2node_ID, E2setupRequestIEs__value_PR_GlobalE2node_ID);
    E2setupRequestIEs_t *rf = add_ie(m, ProtocolIE_ID_id_RANfunctionsAdded, E2setupRequestIEs__value_PR_RANfunctions_List);
    E2setupRequestIEs_t *cc = add_ie(m, ProtocolIE_ID_id_E2nodeComponentConfigAddition,
                                     E2setupRequestIEs__value_PR_E2nodeComponentConfigAddition_List);
    ok = tx && gid && rf && cc;
    if (ok) {
      tx->value.choice.TransactionID = transactionId;
      ok = fill_global_e2node_id(cfg, gid->value.choice.GlobalE2node_ID, err) &&
           fill_ran_functions_list(rf->value.choice.RANfunctions_List, funcs) &&
           add_x2_components(cc->value.choice.E2nodeComponentConfigAddition_List, cfg, err);
    }
  }
  if (ok) ok = aper_encode(&asn_DEF_E2AP_PDU, pdu, out, err);
  else if (err.empty()) err = "E2SetupRequest: out of memory";
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
  return ok;
}

}  // namespace agent
