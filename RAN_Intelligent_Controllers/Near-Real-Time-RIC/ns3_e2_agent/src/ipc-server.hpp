// ns3-e2-ipc v1 server: TCP listen socket, one client at a time, newline-
// delimited JSON lines of at most 1 MiB. Since minor 1 the agent writes
// `control` lines to ns-3; they are queued and flushed without blocking.
#ifndef NS3_E2_AGENT_IPC_SERVER_HPP
#define NS3_E2_AGENT_IPC_SERVER_HPP

#include <string>
#include <vector>

namespace agent {

class IpcServer {
 public:
  ~IpcServer();
  bool listen(int port, std::string &err);
  int listen_fd() const { return lfd_; }
  int client_fd() const { return cfd_; }
  // Accepts a pending connection; a second concurrent client is closed.
  // Returns true when a new client became the active one.
  bool on_accept();
  // Reads available bytes from the client and returns complete lines.
  // On EOF, error or an over-long line the client is closed.
  void on_readable(std::vector<std::string> &lines);
  void close_client(const char *why);
  // Queues one complete line for the client and tries to send it; false when no client.
  bool send_line(const std::string &line);
  // Sends queued bytes; call when poll reports POLLOUT.
  void flush();
  bool want_write() const { return !out_.empty(); }

 private:
  int lfd_ = -1, cfd_ = -1;
  std::string buf_;
  std::string out_;  // queued outbound bytes
};

constexpr size_t kMaxIpcLine = 1 << 20;

}  // namespace agent

#endif
