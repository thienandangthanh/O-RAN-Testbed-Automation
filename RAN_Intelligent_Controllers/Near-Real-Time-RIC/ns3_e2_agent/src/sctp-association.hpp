// One SCTP association to e2term, owned by the agent (not libe2sim's
// sctp_start_client / client_fd). Non-blocking connect from a fresh socket,
// ephemeral source port by default; sends never block and never raise SIGPIPE.
#ifndef NS3_E2_AGENT_SCTP_ASSOCIATION_HPP
#define NS3_E2_AGENT_SCTP_ASSOCIATION_HPP

#include <string>
#include <vector>

#include "asn-util.hpp"

namespace agent {

class SctpAssociation {
 public:
  enum class SendResult { Sent, Busy, Lost };

  ~SctpAssociation() { close(); }

  // New socket (heartbeat 5 s, path/association max retransmissions 3, NODELAY,
  // association/shutdown events), optional bind to srcPort, non-blocking connect.
  bool start_connect(const std::string &addr, int port, int srcPort, std::string &err);
  // Call when the socket is writable while connecting: true = established.
  bool finish_connect(std::string &err);
  // Reads every complete message available. False = association lost (reason set).
  bool read_messages(std::vector<Bytes> &out, std::string &reason);
  // One E2AP message, MSG_NOSIGNAL | MSG_DONTWAIT (stream 0, PPID 0 as NIST's e2sim).
  SendResult send(const Bytes &msg, std::string &err);
  void close();

  int fd() const { return fd_; }
  bool connecting() const { return fd_ >= 0 && connecting_; }
  bool connected() const { return fd_ >= 0 && !connecting_; }
  std::string local_endpoint() const;

 private:
  int fd_ = -1;
  bool connecting_ = false;
  Bytes partial_;  // message without MSG_EOR yet
};

}  // namespace agent

#endif
