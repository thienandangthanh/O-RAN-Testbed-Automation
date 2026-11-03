// Outbound E2AP PDUs (see e2ap-builders.hpp).
#include "e2ap-builders.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "e2-setup-request.hpp"
#include "encode_e2apv1.hpp"  // NIST libe2sim generators (unmodified)

extern "C" {
#include "E2AP-PDU.h"
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

}  // namespace

bool build_subscription_response(long requestorId, long instanceId, long ranFuncId,
                                 const std::vector<long> &admittedIds,
                                 const std::vector<std::pair<long, long>> &notAdmitted, Bytes &out,
                                 std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  std::vector<long> admitted(admittedIds);
  long none[1] = {0};
  // reject_size 0: the generator's not-admitted branch corrupts the PDU, so it is
  // never used; the not-admitted list is built below instead.
  encoding::generate_e2apv1_subscription_response_success(pdu, admitted.data(), none, (int)admitted.size(), 0,
                                                           requestorId, instanceId);
  bool patched = false;
  auto &list = pdu->choice.successfulOutcome->value.choice.RICsubscriptionResponse.protocolIEs.list;
  for (int i = 0; i < list.count; i++)
    if (list.array[i]->value.present == RICsubscriptionResponse_IEs__value_PR_RANfunctionID) {
      list.array[i]->value.choice.RANfunctionID = ranFuncId;  // generator hard-codes 147
      patched = true;
    }
  if (!notAdmitted.empty()) {
    // Criticalities per the E2AP v03.01 ASN.1: the list IE reject, each item ignore.
    auto *ie = (RICsubscriptionResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionResponse_IEs_t));
    ie->id = ProtocolIE_ID_id_RICactions_NotAdmitted;
    ie->criticality = Criticality_reject;
    ie->value.present = RICsubscriptionResponse_IEs__value_PR_RICaction_NotAdmitted_List;
    for (const auto &na : notAdmitted) {
      auto *it = (RICaction_NotAdmitted_ItemIEs_t *)calloc(1, sizeof(RICaction_NotAdmitted_ItemIEs_t));
      it->id = ProtocolIE_ID_id_RICaction_NotAdmitted_Item;
      it->criticality = Criticality_ignore;
      it->value.present = RICaction_NotAdmitted_ItemIEs__value_PR_RICaction_NotAdmitted_Item;
      it->value.choice.RICaction_NotAdmitted_Item.ricActionID = na.first;
      it->value.choice.RICaction_NotAdmitted_Item.cause.present = Cause_PR_ricRequest;
      it->value.choice.RICaction_NotAdmitted_Item.cause.choice.ricRequest = na.second;
      ASN_SEQUENCE_ADD(&ie->value.choice.RICaction_NotAdmitted_List.list, it);
    }
    ASN_SEQUENCE_ADD(&list, ie);
  }
  return finish(pdu, patched, "RICsubscriptionResponse", out, err);
}

bool build_subscription_failure(long requestorId, long instanceId, long ranFuncId, long ricRequestCause, Bytes &out,
                                std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  pdu->present = E2AP_PDU_PR_unsuccessfulOutcome;
  auto *uo = (UnsuccessfulOutcome_t *)calloc(1, sizeof(UnsuccessfulOutcome_t));
  pdu->choice.unsuccessfulOutcome = uo;
  uo->procedureCode = ProcedureCode_id_RICsubscription;
  uo->criticality = Criticality_reject;
  uo->value.present = UnsuccessfulOutcome__value_PR_RICsubscriptionFailure;
  auto &list = uo->value.choice.RICsubscriptionFailure.protocolIEs.list;
  // Criticalities per the E2AP v03.01 ASN.1 (RICsubscriptionFailure-IEs): all reject.
  auto add = [&list](long id) {
    auto *ie = (RICsubscriptionFailure_IEs_t *)calloc(1, sizeof(RICsubscriptionFailure_IEs_t));
    ie->id = id;
    ie->criticality = Criticality_reject;
    ASN_SEQUENCE_ADD(&list, ie);
    return ie;
  };
  RICsubscriptionFailure_IEs_t *req = add(ProtocolIE_ID_id_RICrequestID);
  req->value.present = RICsubscriptionFailure_IEs__value_PR_RICrequestID;
  req->value.choice.RICrequestID.ricRequestorID = requestorId;
  req->value.choice.RICrequestID.ricInstanceID = instanceId;
  RICsubscriptionFailure_IEs_t *fn = add(ProtocolIE_ID_id_RANfunctionID);
  fn->value.present = RICsubscriptionFailure_IEs__value_PR_RANfunctionID;
  fn->value.choice.RANfunctionID = ranFuncId;
  RICsubscriptionFailure_IEs_t *ca = add(ProtocolIE_ID_id_Cause);
  ca->value.present = RICsubscriptionFailure_IEs__value_PR_Cause;
  ca->value.choice.Cause.present = Cause_PR_ricRequest;
  ca->value.choice.Cause.choice.ricRequest = ricRequestCause;
  return finish(pdu, true, "RICsubscriptionFailure", out, err);
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

bool build_service_update(const std::vector<RanFunctionSpec> &funcs, long transactionId, Bytes &out, std::string &err) {
  E2AP_PDU_t *pdu = new_pdu();
  pdu->present = E2AP_PDU_PR_initiatingMessage;
  auto *im = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  pdu->choice.initiatingMessage = im;
  im->procedureCode = ProcedureCode_id_RICserviceUpdate;
  im->criticality = Criticality_reject;
  im->value.present = InitiatingMessage__value_PR_RICserviceUpdate;
  auto &list = im->value.choice.RICserviceUpdate.protocolIEs.list;
  using IE = RICserviceUpdate_IEs_t;
  IE *tx = add_ie<IE>(list, ProtocolIE_ID_id_TransactionID, Criticality_reject);
  tx->value.present = RICserviceUpdate_IEs__value_PR_TransactionID;
  tx->value.choice.TransactionID = transactionId;
  IE *mod = add_ie<IE>(list, ProtocolIE_ID_id_RANfunctionsModified, Criticality_reject);
  mod->value.present = RICserviceUpdate_IEs__value_PR_RANfunctions_List_1;  // the Modified alternative
  bool ok = fill_ran_functions_list(mod->value.choice.RANfunctions_List_1, funcs);
  return finish(pdu, ok, "RICserviceUpdate", out, err);
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
