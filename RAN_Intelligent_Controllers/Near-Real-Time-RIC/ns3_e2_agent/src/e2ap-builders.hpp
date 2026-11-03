// Outbound E2AP PDUs after setup (the E2SetupRequest is in e2-setup-request.hpp).
// Subscription response and indication come from NIST's libe2sim generators
// (unmodified) and are post-edited in place before encoding; the others are
// agent-owned.
#ifndef NS3_E2_AGENT_E2AP_BUILDERS_HPP
#define NS3_E2_AGENT_E2AP_BUILDERS_HPP

#include <utility>
#include <vector>

#include "agent-config.hpp"
#include "asn-util.hpp"
#include "e2-setup-request.hpp"

namespace agent {

// RICsubscriptionResponse: the generator's admitted list (its hard-coded
// RANfunctionID 147 replaced with the request's function ID) plus, when
// notAdmitted is not empty, an agent-built RICactions-NotAdmitted list
// (E2AP v03.00 9.1.1.2) of (action ID, ricRequest cause) items.
bool build_subscription_response(long requestorId, long instanceId, long ranFuncId,
                                 const std::vector<long> &admitted,
                                 const std::vector<std::pair<long, long>> &notAdmitted, Bytes &out,
                                 std::string &err);

// RICsubscriptionFailure (agent-owned builder; E2AP v03.00 9.1.1.3) with a
// ricRequest cause (CauseRICrequest value).
bool build_subscription_failure(long requestorId, long instanceId, long ranFuncId, long ricRequestCause, Bytes &out,
                                std::string &err);

// RICsubscriptionDeleteResponse (agent-owned builder).
bool build_subscription_delete_response(long requestorId, long instanceId, long ranFuncId, Bytes &out,
                                        std::string &err);

// RICserviceUpdate answering a RICserviceQuery (agent-owned builder; E2AP
// v03.00 9.1.1.4): the query's TransactionID and every RAN function of the
// node as RANfunctionsModified.
bool build_service_update(const std::vector<RanFunctionSpec> &funcs, long transactionId, Bytes &out, std::string &err);

// RICcontrolAcknowledge (agent-owned builder; E2AP v03.00 9.1.1.9): RIC Request
// ID, RAN Function ID, RIC Call Process ID if the request had one, and the
// E2SM RIC Control Outcome octets.
bool build_control_ack(long requestorId, long instanceId, long ranFuncId, const Bytes *callProcessId,
                       const Bytes &outcome, Bytes &out, std::string &err);

// RICcontrolFailure (agent-owned builder; E2AP v03.00 9.1.1.10) with a
// ricRequest cause (CauseRICrequest value).
bool build_control_failure(long requestorId, long instanceId, long ranFuncId, const Bytes *callProcessId,
                           long ricRequestCause, Bytes &out, std::string &err);

// RICindication (REPORT) carrying one E2SM header + message; refuses messages
// larger than the generator's fixed 8192-byte copy buffer.
bool build_indication(long requestorId, long instanceId, long ranFuncId, long actionId, long sn,
                      const Bytes &hdr, const Bytes &msg, Bytes &out, std::string &err);

}  // namespace agent

#endif
