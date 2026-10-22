// Inbound E2AP decoding and summary (see e2ap-inbound.hpp).
#include "e2ap-inbound.hpp"

#include "asn-util.hpp"

extern "C" {
#include "E2AP-PDU.h"
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "SuccessfulOutcome.h"
#include "UnsuccessfulOutcome.h"
}

namespace agent {

namespace {

void summarize_subscription(const RICsubscriptionRequest_t &r, InboundPdu &o) {
  for (int i = 0; i < r.protocolIEs.list.count; i++) {
    const RICsubscriptionRequest_IEs_t *ie = r.protocolIEs.list.array[i];
    switch (ie->value.present) {
      case RICsubscriptionRequest_IEs__value_PR_RICrequestID:
        o.requestorId = ie->value.choice.RICrequestID.ricRequestorID;
        o.instanceId = ie->value.choice.RICrequestID.ricInstanceID;
        break;
      case RICsubscriptionRequest_IEs__value_PR_RANfunctionID:
        o.ranFuncId = ie->value.choice.RANfunctionID;
        break;
      case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails: {
        const auto &acts = ie->value.choice.RICsubscriptionDetails.ricAction_ToBeSetup_List.list;
        for (int k = 0; k < acts.count; k++) {
          const auto *a = (const RICaction_ToBeSetup_ItemIEs_t *)acts.array[k];
          o.actionIds.push_back(a->value.choice.RICaction_ToBeSetup_Item.ricActionID);
          o.actionTypes.push_back(a->value.choice.RICaction_ToBeSetup_Item.ricActionType);
        }
        break;
      }
      default:
        break;
    }
  }
}

void summarize_delete(const RICsubscriptionDeleteRequest_t &r, InboundPdu &o) {
  for (int i = 0; i < r.protocolIEs.list.count; i++) {
    const RICsubscriptionDeleteRequest_IEs_t *ie = r.protocolIEs.list.array[i];
    if (ie->value.present == RICsubscriptionDeleteRequest_IEs__value_PR_RICrequestID) {
      o.requestorId = ie->value.choice.RICrequestID.ricRequestorID;
      o.instanceId = ie->value.choice.RICrequestID.ricInstanceID;
    } else if (ie->value.present == RICsubscriptionDeleteRequest_IEs__value_PR_RANfunctionID) {
      o.ranFuncId = ie->value.choice.RANfunctionID;
    }
  }
}

void summarize_setup_response(const E2setupResponse_t &r, InboundPdu &o) {
  for (int i = 0; i < r.protocolIEs.list.count; i++) {
    const E2setupResponseIEs_t *ie = r.protocolIEs.list.array[i];
    if (ie->value.present == E2setupResponseIEs__value_PR_TransactionID) {
      o.transactionId = ie->value.choice.TransactionID;
    } else if (ie->value.present == E2setupResponseIEs__value_PR_RANfunctionsID_List) {
      const auto &l = ie->value.choice.RANfunctionsID_List.list;
      for (int k = 0; k < l.count; k++)
        o.funcsAccepted.push_back(((const RANfunctionID_ItemIEs_t *)l.array[k])->value.choice.RANfunctionID_Item.ranFunctionID);
    } else if (ie->value.present == E2setupResponseIEs__value_PR_RANfunctionsIDcause_List) {
      const auto &l = ie->value.choice.RANfunctionsIDcause_List.list;
      for (int k = 0; k < l.count; k++)
        o.funcsRejected.push_back(
            ((const RANfunctionIDcause_ItemIEs_t *)l.array[k])->value.choice.RANfunctionIDcause_Item.ranFunctionID);
    }
  }
}

void summarize_control(const RICcontrolRequest_t &r, InboundPdu &o) {
  for (int i = 0; i < r.protocolIEs.list.count; i++) {
    const RICcontrolRequest_IEs_t *ie = r.protocolIEs.list.array[i];
    const auto &v = ie->value.choice;
    switch (ie->value.present) {
      case RICcontrolRequest_IEs__value_PR_RICrequestID:
        o.requestorId = v.RICrequestID.ricRequestorID;
        o.instanceId = v.RICrequestID.ricInstanceID;
        break;
      case RICcontrolRequest_IEs__value_PR_RANfunctionID: o.ranFuncId = v.RANfunctionID; break;
      case RICcontrolRequest_IEs__value_PR_RICcallProcessID:
        o.hasCallProcessId = true;
        o.callProcessId.assign(v.RICcallProcessID.buf, v.RICcallProcessID.buf + v.RICcallProcessID.size);
        break;
      case RICcontrolRequest_IEs__value_PR_RICcontrolHeader:
        o.controlHeader.assign(v.RICcontrolHeader.buf, v.RICcontrolHeader.buf + v.RICcontrolHeader.size);
        break;
      case RICcontrolRequest_IEs__value_PR_RICcontrolMessage:
        o.controlMessage.assign(v.RICcontrolMessage.buf, v.RICcontrolMessage.buf + v.RICcontrolMessage.size);
        break;
      case RICcontrolRequest_IEs__value_PR_RICcontrolAckRequest: o.controlAckRequest = v.RICcontrolAckRequest; break;
      default: break;
    }
  }
}

void summarize_query(const RICserviceQuery_t &r, InboundPdu &o) {
  for (int i = 0; i < r.protocolIEs.list.count; i++)
    if (r.protocolIEs.list.array[i]->value.present == RICserviceQuery_IEs__value_PR_TransactionID)
      o.transactionId = r.protocolIEs.list.array[i]->value.choice.TransactionID;
}

void summarize(const E2AP_PDU_t *pdu, InboundPdu &o) {
  o.pduPresent = (int)pdu->present;
  if (pdu->present == E2AP_PDU_PR_initiatingMessage) {
    const InitiatingMessage_t *m = pdu->choice.initiatingMessage;
    o.procedureCode = m->procedureCode;
    switch (m->procedureCode) {
      case ProcedureCode_id_RICsubscription:
        o.kind = InboundPdu::SubscriptionRequest;
        summarize_subscription(m->value.choice.RICsubscriptionRequest, o);
        break;
      case ProcedureCode_id_RICsubscriptionDelete:
        o.kind = InboundPdu::SubscriptionDeleteRequest;
        summarize_delete(m->value.choice.RICsubscriptionDeleteRequest, o);
        break;
      case ProcedureCode_id_RICserviceQuery:
        o.kind = InboundPdu::ServiceQuery;
        summarize_query(m->value.choice.RICserviceQuery, o);
        break;
      case ProcedureCode_id_ErrorIndication: o.kind = InboundPdu::ErrorIndication; break;
      case ProcedureCode_id_Reset: o.kind = InboundPdu::ResetRequest; break;
      case ProcedureCode_id_RICcontrol:
        o.kind = InboundPdu::ControlRequest;
        summarize_control(m->value.choice.RICcontrolRequest, o);
        break;
      default: break;
    }
  } else if (pdu->present == E2AP_PDU_PR_successfulOutcome) {
    const SuccessfulOutcome_t *m = pdu->choice.successfulOutcome;
    o.procedureCode = m->procedureCode;
    if (m->procedureCode == ProcedureCode_id_E2setup) {
      o.kind = InboundPdu::SetupResponse;
      summarize_setup_response(m->value.choice.E2setupResponse, o);
    } else if (m->procedureCode == ProcedureCode_id_RICserviceUpdate) {
      o.kind = InboundPdu::ServiceUpdateAck;
    }
  } else if (pdu->present == E2AP_PDU_PR_unsuccessfulOutcome) {
    const UnsuccessfulOutcome_t *m = pdu->choice.unsuccessfulOutcome;
    o.procedureCode = m->procedureCode;
    if (m->procedureCode == ProcedureCode_id_E2setup) o.kind = InboundPdu::SetupFailure;
    else if (m->procedureCode == ProcedureCode_id_RICserviceUpdate) o.kind = InboundPdu::ServiceUpdateFailure;
  }
}

}  // namespace

const char *inbound_kind_name(InboundPdu::Kind k) {
  static const char *names[] = {"Other", "E2SetupResponse", "E2SetupFailure", "RICsubscriptionRequest",
                                "RICsubscriptionDeleteRequest", "RICserviceQuery", "RICserviceUpdateAcknowledge",
                                "RICserviceUpdateFailure", "ErrorIndication", "ResetRequest", "RICcontrolRequest"};
  return names[k];
}

bool decode_inbound(const uint8_t *buf, size_t len, InboundPdu &out, std::string &err) {
  out = InboundPdu{};
  void *p = nullptr;
  if (!aper_decode_clean(&asn_DEF_E2AP_PDU, &p, buf, len, err)) {
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
    return false;
  }
  summarize((const E2AP_PDU_t *)p, out);
  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, p);
  return true;
}

}  // namespace agent
