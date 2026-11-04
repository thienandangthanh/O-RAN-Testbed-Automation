// RC control path: an inbound RICcontrolRequest (E2SM-RC CONTROL Style 5
// "Dual Connectivity control", action 3 "DC PSCell Change control", header
// UE ID en-gNB-UEID) is checked and decoded here, forwarded to ns-3 as an
// ns3-e2-ipc `control` line naming the UE by {mEnbUeX2apId, mnCellId}, and
// answered on the E2 association once ns-3's `controlAck` arrives:
//   applied             -> RICcontrolAcknowledge with E2SM-RC ControlOutcome
//                          Format 1 (empty ranP-List), unless Ack Request = NoAck;
//   refused (ns-3), late,
//   ns-3 gone (bye/EOF) -> RICcontrolFailure ricRequest control-failed-to-execute.
// Agent-local rejects (no IPC line, answered at once):
//   RAN function != 3, or any control on
//   a node that does not announce RAN
//   function 3 (the eNB)             -> ran-function-id-invalid;
//   E2SM-RC decode error             -> control-message-invalid;
//   style/action != 5/3              -> action-not-supported;
//   a UE ID that is not en-gNB-UEID with
//   a macro eNB ID, an optional member,
//   a UE ID PLMN other than this node's,
//   or a target that is not a strict
//   NR CGI                           -> control-message-invalid;
//   ns-3 not connected               -> control-failed-to-execute.
// Pending controls are keyed by an agent-monotonic ctlId and have no
// wall-clock timer: every request gets exactly one terminal answer.
#ifndef NS3_E2_AGENT_RC_CONTROL_HPP
#define NS3_E2_AGENT_RC_CONTROL_HPP

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <string>

#include <nlohmann/json.hpp>

#include "asn-util.hpp"
#include "e2ap-inbound.hpp"

namespace agent {

constexpr long kRcRanFunctionId = 3;
constexpr long kRcStyleDualConnectivity = 5;   // E2SM-RC v03.00 7.6.6.1
constexpr long kRcActionDcPscellChange = 3;

// The target cell of RAN parameter 4 (NR CGI): the APER NR-CGI, decoded strictly
// (9 octets that re-encode to themselves, rcc_decode_nr_cgi_strict), with this
// node's PLMN and the NR Cell Identity gNB ID || cell part 1 (plan R-3). The
// gNB ID is the target's ns-3 cellId.
struct TargetCell {
  uint32_t gnbId = 0;
  uint16_t cellId = 0;
};
bool parse_target_nr_cgi(const uint8_t *o, size_t n, const std::array<uint8_t, 3> &plmn, TargetCell &out,
                         std::string &err);

struct PendingControl {
  long requestorId = -1, instanceId = -1, ranFuncId = -1;
  bool hasCallProcessId = false;
  Bytes callProcessId;
  bool noAck = false;  // RIC Control Ack Request = NoAck
};

class RcControlPath {
 public:
  using SendE2 = std::function<void(const Bytes &pdu, const char *what)>;
  using SendIpc = std::function<bool(const std::string &line)>;  // false: not sent

  // rcAnnounced: the node announces RAN function 3 (a gNB); on the eNB every control is refused
  // ran-function-id-invalid.
  RcControlPath(int nodeId, const std::array<uint8_t, 3> &plmn, bool rcAnnounced, SendE2 sendE2, SendIpc sendIpc);

  // A RICcontrolRequest. afterSeq is the last sample seq received from ns-3;
  // ipcUp is true while ns-3 is connected and its hello was accepted.
  void on_request(const InboundPdu &p, int64_t afterSeq, bool ipcUp);

  // A `controlAck` line from ns-3.
  void on_control_ack(const nlohmann::json &m);

  // ns-3 sent bye or the IPC connection closed: every pending control fails.
  void fail_all_pending(const char *why);

  size_t pending() const { return pending_.size(); }

 private:
  void answer_failure(const PendingControl &c, long cause, const char *why);
  void answer_ack(const PendingControl &c);

  int nodeId_;
  std::array<uint8_t, 3> plmn_;
  bool rcAnnounced_;
  SendE2 sendE2_;
  SendIpc sendIpc_;
  uint64_t nextCtlId_ = 1;
  std::map<uint64_t, PendingControl> pending_;
};

}  // namespace agent

#endif
