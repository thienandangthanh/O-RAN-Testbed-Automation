// Inbound E2AP PDUs from e2term, decoded into a small flat summary so the
// session logic never touches asn1c structures.
#ifndef NS3_E2_AGENT_E2AP_INBOUND_HPP
#define NS3_E2_AGENT_E2AP_INBOUND_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace agent {

struct InboundPdu {
  enum Kind {
    Other,
    SetupResponse,
    SetupFailure,
    SubscriptionRequest,
    SubscriptionDeleteRequest,
    ServiceQuery,
    ServiceUpdateAck,
    ServiceUpdateFailure,
    ErrorIndication,
    ResetRequest,
    ControlRequest,
  } kind = Other;
  long procedureCode = -1;
  int pduPresent = 0;            // 1 initiating, 2 successful, 3 unsuccessful
  long requestorId = -1, instanceId = -1, ranFuncId = -1, transactionId = -1;
  // RICsubscriptionRequest: the E2SM event trigger octets and, per action in
  // request order, its ID, RICactionType (0 = report) and E2SM action definition
  // octets (empty with actionHasDefinition false when the optional IE is absent).
  std::vector<uint8_t> eventTrigger;
  std::vector<long> actionIds;
  std::vector<long> actionTypes;
  std::vector<std::vector<uint8_t>> actionDefinitions;
  std::vector<bool> actionHasDefinition;
  std::vector<long> funcsAccepted, funcsRejected;  // E2SetupResponse
  // RICcontrolRequest
  std::vector<uint8_t> controlHeader, controlMessage, callProcessId;
  bool hasCallProcessId = false;
  long controlAckRequest = -1;   // -1 absent, 0 noAck, 1 ack
};

const char *inbound_kind_name(InboundPdu::Kind k);

// Clean APER decode (RC_OK, all octets consumed) and summary. False + err otherwise.
bool decode_inbound(const uint8_t *buf, size_t len, InboundPdu &out, std::string &err);

}  // namespace agent

#endif
