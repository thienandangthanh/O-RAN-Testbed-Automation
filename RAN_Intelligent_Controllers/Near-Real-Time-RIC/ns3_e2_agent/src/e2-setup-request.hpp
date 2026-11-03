// The agent-owned E2SetupRequest (E2AP v03.00 §9.1.2.1; criticalities per the v03.01 ASN.1) and the RAN functions
// a node announces:
//   gnb -> RAN function 2 (E2SM-KPM, the agent's KPM definition) and RAN function 3 (E2SM-RC, rc_codec's
//          definition: CONTROL Style 3 action 1 and Style 5 action 3);
//   enb -> RAN function 2 only.
// The Global E2 Node ID and the X2 components come from e2-node-identity.hpp. No NIST generator is used: it writes
// the 29-bit gNB choice, an NG component and RANfunction-Item criticality reject (the ASN.1 says ignore).
#ifndef NS3_E2_AGENT_E2_SETUP_REQUEST_HPP
#define NS3_E2_AGENT_E2_SETUP_REQUEST_HPP

#include <string>
#include <vector>

#include "agent-config.hpp"
#include "asn-util.hpp"

extern "C" {
#include "RANfunctions-List.h"
}

namespace agent {

struct RanFunctionSpec {
  long id = 0;
  long revision = 0;
  std::string oid;
  Bytes definition;
};

constexpr long kRcRanFunctionRevision = 1;

// The node's RAN functions in announcement order. False with err if the RC definition cannot be encoded.
bool node_ran_functions(const Config &cfg, const Bytes &kpmDefinition, std::vector<RanFunctionSpec> &out,
                        std::string &err);

// RANfunctions-List items (RANfunction-Item, criticality ignore) for the setup request and the service update.
bool fill_ran_functions_list(RANfunctions_List_t &l, const std::vector<RanFunctionSpec> &funcs);

// E2SetupRequest with TransactionID transactionId (0..255).
bool build_setup_request(const Config &cfg, const std::vector<RanFunctionSpec> &funcs, long transactionId, Bytes &out,
                         std::string &err);

}  // namespace agent

#endif
