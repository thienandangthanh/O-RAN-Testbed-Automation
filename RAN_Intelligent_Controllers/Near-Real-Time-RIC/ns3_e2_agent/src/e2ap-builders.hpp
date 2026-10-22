// Outbound E2AP PDUs. Setup request, subscription response, indication and
// service update come from NIST's libe2sim generators (unmodified) and are
// post-edited in place before encoding; the delete response is agent-owned.
#ifndef NS3_E2_AGENT_E2AP_BUILDERS_HPP
#define NS3_E2_AGENT_E2AP_BUILDERS_HPP

#include <vector>

#include "agent-config.hpp"
#include "asn-util.hpp"

namespace agent {

// E2SetupRequest: generator output with GlobalE2node gNB identity overwritten
// (PLMN BCD, 29-bit gNB-ID, bits_unused 3), our OID, definition and revision.
bool build_setup_request(const Config &cfg, const Bytes &ranFuncDef, Bytes &out, std::string &err);

// RICsubscriptionResponse admitting every action; the generator's hard-coded
// RANfunctionID 147 is replaced with the request's function ID.
bool build_subscription_response(long requestorId, long instanceId, long ranFuncId,
                                 const std::vector<long> &actionIds, Bytes &out, std::string &err);

// RICsubscriptionDeleteResponse (agent-owned builder).
bool build_subscription_delete_response(long requestorId, long instanceId, long ranFuncId, Bytes &out,
                                        std::string &err);

// RICserviceUpdate answering a RICserviceQuery: generator output with our
// function ID, OID and revision restored and the query's TransactionID added.
bool build_service_update(const Config &cfg, const Bytes &ranFuncDef, long transactionId, Bytes &out,
                          std::string &err);

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
