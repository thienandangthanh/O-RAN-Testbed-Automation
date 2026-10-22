// Outbound E2AP PDUs (see e2ap-builders.hpp).
#include "e2ap-builders.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "encode_e2apv1.hpp"  // NIST libe2sim generators (unmodified)

extern "C" {
#include "E2AP-PDU.h"
#include "E2nodeComponentInterfaceNG.h"
#include "GlobalE2node-gNB-ID.h"
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "SuccessfulOutcome.h"
#include "UnsuccessfulOutcome.h"
}

namespace agent {

namespace {

E2AP_PDU_t *new_pdu() { return (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t)); }

bool finish(E2AP_PDU_t *pdu, bool patched, const char *what, Bytes &out, std::string &err) {
  bool ok = patched;
  if (!patched) err = std::string(what) + ": generated PDU did not have the expected shape";
  else ok = aper_encode(&asn_DEF_E2AP_PDU, pdu, out, err);
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
  return ok;
}

// ran_func_info whose definition/OID buffers are handed over to the PDU:
// the generators copy the OCTET_STRING structs by value, so only the shells
// are freed here and ASN_STRUCT_FREE of the PDU releases the buffers.
struct FuncInfo {
  encoding::ran_func_info info{};
  FuncInfo(const Config &cfg, const Bytes &def, long rev) {
    info.ranFunctionId = cfg.ranFuncId;
    info.ranFunctionDesc = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
    OCTET_STRING_fromBuf(info.ranFunctionDesc, (const char *)def.data(), (int)def.size());
    info.ranFunctionRev = rev;
    info.ranFunctionOId = new_octets(cfg.kpmOid);
  }
  ~FuncInfo() {
    free(info.ranFunctionDesc);
    free(info.ranFunctionOId);
  }
};

// The setup generator builds three OCTET STRINGs (amf_name, request part,
// response part) on its stack without zeroing them and copies them into the
// PDU, so their asn1c parsing context is garbage and ASN_STRUCT_FREE crashes on
// it. Zero those contexts in place; the octets themselves are untouched.
// N5 (recorded deviation from E2AP v03.00 9.2.27, which expects the encoded
// 3GPP setup request, here an EN-DC X2 SETUP REQUEST): a gNB agent's request
// part is 5 raw octets, gNB-ID (4, big-endian) then cell id (1), e.g.
// 00 00 00 02 02. e2mgr stores them, and the TS xApp finds the hex text
// "0000000202" there as its cell key; rc turns the same key back into the
// target NR CGI octets. The eNB keeps the generator's "reqpart".
bool set_gnb_request_part(E2setupRequestIEs_t *ie, const Config &cfg) {
  auto &items = ie->value.choice.E2nodeComponentConfigAddition_List.list;
  uint8_t key[5] = {(uint8_t)(cfg.gnbId >> 24), (uint8_t)(cfg.gnbId >> 16), (uint8_t)(cfg.gnbId >> 8),
                    (uint8_t)cfg.gnbId, (uint8_t)cfg.nodeId};
  for (int k = 0; k < items.count; k++) {
    auto *it = (E2nodeComponentConfigAddition_ItemIEs_t *)items.array[k];
    OCTET_STRING_t &rp =
        it->value.choice.E2nodeComponentConfigAddition_Item.e2nodeComponentConfiguration.e2nodeComponentRequestPart;
    if (OCTET_STRING_fromBuf(&rp, (const char *)key, sizeof key) != 0) return false;
  }
  return items.count > 0;
}

void clear_component_config_contexts(E2setupRequestIEs_t *ie) {
  auto &items = ie->value.choice.E2nodeComponentConfigAddition_List.list;
  for (int k = 0; k < items.count; k++) {
    auto *it = (E2nodeComponentConfigAddition_ItemIEs_t *)items.array[k];
    E2nodeComponentConfigAddition_Item_t &c = it->value.choice.E2nodeComponentConfigAddition_Item;
    memset(&c.e2nodeComponentConfiguration.e2nodeComponentRequestPart._asn_ctx, 0, sizeof(asn_struct_ctx_t));
    memset(&c.e2nodeComponentConfiguration.e2nodeComponentResponsePart._asn_ctx, 0, sizeof(asn_struct_ctx_t));
    if (c.e2nodeComponentID.present == E2nodeComponentID_PR_e2nodeComponentInterfaceTypeNG &&
        c.e2nodeComponentID.choice.e2nodeComponentInterfaceTypeNG)
      memset(&c.e2nodeComponentID.choice.e2nodeComponentInterfaceTypeNG->amf_name._asn_ctx, 0,
             sizeof(asn_struct_ctx_t));
  }
}

}  // namespace

bool build_setup_request(const Config &cfg, const Bytes &ranFuncDef, Bytes &out, std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  {
    FuncInfo f(cfg, ranFuncDef, kRanFunctionRevision);
    encoding::generate_e2apv1_setup_request_parameterized(pdu, {f.info});
  }
  bool patched = false, reqPartOk = cfg.kind != "gnb";
  auto &list = pdu->choice.initiatingMessage->value.choice.E2setupRequest.protocolIEs.list;
  for (int i = 0; i < list.count; i++) {
    E2setupRequestIEs_t *ie = list.array[i];
    if (ie->value.present == E2setupRequestIEs__value_PR_E2nodeComponentConfigAddition_List) {
      clear_component_config_contexts(ie);
      if (cfg.kind == "gnb") reqPartOk = set_gnb_request_part(ie, cfg);
    }
    if (ie->value.present != E2setupRequestIEs__value_PR_GlobalE2node_ID) continue;
    GlobalE2node_ID_t &g = ie->value.choice.GlobalE2node_ID;
    if (g.present != GlobalE2node_ID_PR_gNB || !g.choice.gNB) continue;  // unexpected shape: leave patched false
    GlobalgNB_ID_t &gg = g.choice.gNB->global_gNB_ID;
    BIT_STRING_t &id = gg.gnb_id.choice.gnb_ID;
    if (gg.plmn_id.size != 3 || gg.gnb_id.present != GNB_ID_Choice_PR_gnb_ID || id.size != 4 || id.bits_unused != 3)
      continue;
    memcpy(gg.plmn_id.buf, cfg.plmnBcd.data(), 3);  // edit in place: buffers stay generator-owned
    uint32_t v = cfg.gnbId << 3;                     // 29-bit value, left-aligned
    for (int b = 0; b < 4; b++) id.buf[b] = (uint8_t)(v >> (24 - 8 * b));
    patched = true;
  }
  return finish(pdu, patched && reqPartOk, "E2SetupRequest", out, err);
}

bool build_subscription_response(long requestorId, long instanceId, long ranFuncId,
                                 const std::vector<long> &actionIds, Bytes &out, std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  std::vector<long> admitted(actionIds);
  long none[1] = {0};
  // reject_size 0: the generator's not-admitted branch corrupts the PDU, so it is never used.
  encoding::generate_e2apv1_subscription_response_success(pdu, admitted.data(), none, (int)admitted.size(), 0,
                                                           requestorId, instanceId);
  bool patched = false;
  auto &list = pdu->choice.successfulOutcome->value.choice.RICsubscriptionResponse.protocolIEs.list;
  for (int i = 0; i < list.count; i++)
    if (list.array[i]->value.present == RICsubscriptionResponse_IEs__value_PR_RANfunctionID) {
      list.array[i]->value.choice.RANfunctionID = ranFuncId;  // generator hard-codes 147
      patched = true;
    }
  return finish(pdu, patched, "RICsubscriptionResponse", out, err);
}

bool build_subscription_delete_response(long requestorId, long instanceId, long ranFuncId, Bytes &out,
                                        std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  pdu->present = E2AP_PDU_PR_successfulOutcome;
  auto *so = (SuccessfulOutcome_t *)calloc(1, sizeof(SuccessfulOutcome_t));
  pdu->choice.successfulOutcome = so;
  so->procedureCode = ProcedureCode_id_RICsubscriptionDelete;
  so->criticality = Criticality_reject;
  so->value.present = SuccessfulOutcome__value_PR_RICsubscriptionDeleteResponse;
  auto &list = so->value.choice.RICsubscriptionDeleteResponse.protocolIEs.list;

  auto *req = (RICsubscriptionDeleteResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionDeleteResponse_IEs_t));
  req->id = ProtocolIE_ID_id_RICrequestID;
  req->criticality = Criticality_reject;
  req->value.present = RICsubscriptionDeleteResponse_IEs__value_PR_RICrequestID;
  req->value.choice.RICrequestID.ricRequestorID = requestorId;
  req->value.choice.RICrequestID.ricInstanceID = instanceId;
  ASN_SEQUENCE_ADD(&list, req);

  auto *fn = (RICsubscriptionDeleteResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionDeleteResponse_IEs_t));
  fn->id = ProtocolIE_ID_id_RANfunctionID;
  fn->criticality = Criticality_reject;
  fn->value.present = RICsubscriptionDeleteResponse_IEs__value_PR_RANfunctionID;
  fn->value.choice.RANfunctionID = ranFuncId;
  ASN_SEQUENCE_ADD(&list, fn);
  return finish(pdu, true, "RICsubscriptionDeleteResponse", out, err);
}

namespace {
// Adds one protocol IE to a control answer; criticalities per E2AP v03.00 9.1.1.9/9.1.1.10.
template <typename IE, typename List>
IE *add_ie(List &list, long id, long criticality) {
  auto *ie = (IE *)calloc(1, sizeof(IE));
  ie->id = id;
  ie->criticality = criticality;
  ASN_SEQUENCE_ADD(&list, ie);
  return ie;
}
}  // namespace

bool build_control_ack(long requestorId, long instanceId, long ranFuncId, const Bytes *callProcessId,
                       const Bytes &outcome, Bytes &out, std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  pdu->present = E2AP_PDU_PR_successfulOutcome;
  auto *so = (SuccessfulOutcome_t *)calloc(1, sizeof(SuccessfulOutcome_t));
  pdu->choice.successfulOutcome = so;
  so->procedureCode = ProcedureCode_id_RICcontrol;
  so->criticality = Criticality_reject;
  so->value.present = SuccessfulOutcome__value_PR_RICcontrolAcknowledge;
  auto &list = so->value.choice.RICcontrolAcknowledge.protocolIEs.list;
  using IE = RICcontrolAcknowledge_IEs_t;
  IE *req = add_ie<IE>(list, ProtocolIE_ID_id_RICrequestID, Criticality_reject);
  req->value.present = RICcontrolAcknowledge_IEs__value_PR_RICrequestID;
  req->value.choice.RICrequestID.ricRequestorID = requestorId;
  req->value.choice.RICrequestID.ricInstanceID = instanceId;
  IE *fn = add_ie<IE>(list, ProtocolIE_ID_id_RANfunctionID, Criticality_reject);
  fn->value.present = RICcontrolAcknowledge_IEs__value_PR_RANfunctionID;
  fn->value.choice.RANfunctionID = ranFuncId;
  if (callProcessId) {
    IE *cp = add_ie<IE>(list, ProtocolIE_ID_id_RICcallProcessID, Criticality_reject);
    cp->value.present = RICcontrolAcknowledge_IEs__value_PR_RICcallProcessID;
    OCTET_STRING_fromBuf(&cp->value.choice.RICcallProcessID, (const char *)callProcessId->data(),
                         (int)callProcessId->size());
  }
  IE *oc = add_ie<IE>(list, ProtocolIE_ID_id_RICcontrolOutcome, Criticality_reject);
  oc->value.present = RICcontrolAcknowledge_IEs__value_PR_RICcontrolOutcome;
  OCTET_STRING_fromBuf(&oc->value.choice.RICcontrolOutcome, (const char *)outcome.data(), (int)outcome.size());
  return finish(pdu, true, "RICcontrolAcknowledge", out, err);
}

bool build_control_failure(long requestorId, long instanceId, long ranFuncId, const Bytes *callProcessId,
                           long ricRequestCause, Bytes &out, std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  pdu->present = E2AP_PDU_PR_unsuccessfulOutcome;
  auto *uo = (UnsuccessfulOutcome_t *)calloc(1, sizeof(UnsuccessfulOutcome_t));
  pdu->choice.unsuccessfulOutcome = uo;
  uo->procedureCode = ProcedureCode_id_RICcontrol;
  uo->criticality = Criticality_reject;
  uo->value.present = UnsuccessfulOutcome__value_PR_RICcontrolFailure;
  auto &list = uo->value.choice.RICcontrolFailure.protocolIEs.list;
  using IE = RICcontrolFailure_IEs_t;
  IE *req = add_ie<IE>(list, ProtocolIE_ID_id_RICrequestID, Criticality_reject);
  req->value.present = RICcontrolFailure_IEs__value_PR_RICrequestID;
  req->value.choice.RICrequestID.ricRequestorID = requestorId;
  req->value.choice.RICrequestID.ricInstanceID = instanceId;
  IE *fn = add_ie<IE>(list, ProtocolIE_ID_id_RANfunctionID, Criticality_reject);
  fn->value.present = RICcontrolFailure_IEs__value_PR_RANfunctionID;
  fn->value.choice.RANfunctionID = ranFuncId;
  if (callProcessId) {
    IE *cp = add_ie<IE>(list, ProtocolIE_ID_id_RICcallProcessID, Criticality_reject);
    cp->value.present = RICcontrolFailure_IEs__value_PR_RICcallProcessID;
    OCTET_STRING_fromBuf(&cp->value.choice.RICcallProcessID, (const char *)callProcessId->data(),
                         (int)callProcessId->size());
  }
  IE *ca = add_ie<IE>(list, ProtocolIE_ID_id_Cause, Criticality_ignore);
  ca->value.present = RICcontrolFailure_IEs__value_PR_Cause;
  ca->value.choice.Cause.present = Cause_PR_ricRequest;
  ca->value.choice.Cause.choice.ricRequest = ricRequestCause;
  return finish(pdu, true, "RICcontrolFailure", out, err);
}

bool build_service_update(const Config &cfg, const Bytes &ranFuncDef, long transactionId, Bytes &out,
                          std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  {
    FuncInfo f(cfg, ranFuncDef, kRanFunctionRevision);
    encoding::generate_e2apv1_service_update(pdu, {f.info});  // "Modified" (RAN_FUNCTION_OP_TYPE unset)
    free(f.info.ranFunctionOId->buf);  // this generator does not take the OID
    f.info.ranFunctionOId->buf = nullptr;
  }
  bool patched = false;
  auto &list = pdu->choice.initiatingMessage->value.choice.RICserviceUpdate.protocolIEs.list;
  for (int i = 0; i < list.count; i++) {
    RICserviceUpdate_IEs_t *ie = list.array[i];
    if (ie->id != ProtocolIE_ID_id_RANfunctionsModified ||
        ie->value.present != RICserviceUpdate_IEs__value_PR_RANfunctions_List)
      continue;
    ie->value.present = RICserviceUpdate_IEs__value_PR_RANfunctions_List_1;  // the Modified alternative
    auto &items = ie->value.choice.RANfunctions_List_1.list;
    for (int k = 0; k < items.count; k++) {
      auto *it = (RANfunction_ItemIEs_t *)items.array[k];
      RANfunction_Item_t &f = it->value.choice.RANfunction_Item;
      f.ranFunctionID = cfg.ranFuncId;             // generator writes 1
      f.ranFunctionRevision = kRanFunctionRevision;  // generator writes rev + 1
      set_octets(&f.ranFunctionOID, cfg.kpmOid);   // generator leaves it empty
      patched = true;
    }
  }
  auto *tx = (RICserviceUpdate_IEs_t *)calloc(1, sizeof(RICserviceUpdate_IEs_t));
  tx->id = ProtocolIE_ID_id_TransactionID;
  tx->criticality = Criticality_reject;
  tx->value.present = RICserviceUpdate_IEs__value_PR_TransactionID;
  tx->value.choice.TransactionID = transactionId;
  ASN_SEQUENCE_ADD(&list, tx);
  std::rotate(list.array, list.array + list.count - 1, list.array + list.count);  // TransactionID first
  return finish(pdu, patched, "RICserviceUpdate", out, err);
}

bool build_indication(long requestorId, long instanceId, long ranFuncId, long actionId, long sn,
                      const Bytes &hdr, const Bytes &msg, Bytes &out, std::string &err) {
  if (hdr.empty() || msg.empty() || msg.size() > (size_t)kGeneratorMessageLimit) {
    err = "indication: E2SM message size " + std::to_string(msg.size()) + " outside 1.." +
          std::to_string(kGeneratorMessageLimit);
    return false;
  }
  E2AP_PDU_t *pdu = new_pdu();
  encoding::generate_e2apv1_indication_request_parameterized(
      pdu, requestorId, instanceId, ranFuncId, actionId, sn, const_cast<uint8_t *>(hdr.data()), (int)hdr.size(),
      const_cast<uint8_t *>(msg.data()), (int)msg.size());
  return finish(pdu, true, "RICindication", out, err);
}

}  // namespace agent
