// E2 session state machine (crash-only):
//   HOLDOFF (E2_CONNECT_HOLDOFF_S) -> CONNECTING (fresh socket per attempt,
//   E2_CONNECT_TIMEOUT_S per attempt, retry every E2_CONNECT_RETRY_S, forever)
//   -> SETUP_SENT (no E2SetupResponse within E2_SETUP_TIMEOUT_S: exit 3)
//   -> READY (subscriptions, deletes, service queries; undecodable PDUs are
//   logged and counted). Association loss in SETUP_SENT/READY: exit 2, and
//   Docker's restart policy brings the agent back through HOLDOFF.
#ifndef NS3_E2_AGENT_E2_SESSION_HPP
#define NS3_E2_AGENT_E2_SESSION_HPP

#include <cstdint>

#include "agent-config.hpp"
#include "e2ap-inbound.hpp"
#include "sample-forwarder.hpp"
#include "sctp-association.hpp"
#include "subscription-table.hpp"

namespace agent {

class E2Session {
 public:
  enum class State { Holdoff, Connecting, SetupSent, Ready };

  E2Session(const Config &cfg, const Bytes &ranFuncDef, int64_t nowMs);
  // Timer work: hold-off expiry, connect timeout/retry, setup timeout.
  void tick(int64_t nowMs);
  // Socket to poll (-1 if none) and the events wanted.
  int poll_fd(short &events) const;
  void on_poll(short revents, int64_t nowMs);
  bool ready() const { return state_ == State::Ready; }
  // Orderly stop (SIGTERM): end the association with SHUTDOWN, bounded.
  void stop(int timeoutMs) { sctp_.graceful_close(timeoutMs); }
  size_t subscriptions() const { return subs_.size(); }
  // Sends the sample's indications under every subscription (option A).
  // Returns true when every indication was sent.
  bool forward(const EncodedSample &s);

 private:
  void set_state(State s);
  void start_attempt(int64_t nowMs);
  void attempt_failed(const std::string &why, int64_t nowMs);
  void handle_pdu(const Bytes &pdu);
  void on_subscription(const InboundPdu &p);
  void send_ctrl(const Bytes &pdu, const char *what);

  const Config &cfg_;
  const Bytes &ranFuncDef_;
  State state_ = State::Holdoff;
  int64_t deadlineMs_ = 0;  // hold-off end, connect timeout, retry time or setup timeout
  bool waitingRetry_ = false;
  SctpAssociation sctp_;
  SubscriptionTable subs_;
};

}  // namespace agent

#endif
