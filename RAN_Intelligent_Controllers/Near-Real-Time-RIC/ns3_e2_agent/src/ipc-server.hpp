// ns3-e2-ipc v1 server: TCP listen socket, one client at a time, newline-
// delimited JSON lines of at most 1 MiB. v1 is ns-3 -> agent only; the agent
// never writes on the socket.
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

 private:
  int lfd_ = -1, cfd_ = -1;
  std::string buf_;
};

constexpr size_t kMaxIpcLine = 1 << 20;

}  // namespace agent

#endif
