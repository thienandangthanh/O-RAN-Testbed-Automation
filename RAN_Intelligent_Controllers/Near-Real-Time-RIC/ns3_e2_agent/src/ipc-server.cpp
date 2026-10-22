// ns3-e2-ipc v1 TCP server (see ipc-server.hpp).
#include "ipc-server.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "agent-log.hpp"
#include "agent-stats.hpp"

namespace agent {

IpcServer::~IpcServer() {
  if (cfd_ >= 0) ::close(cfd_);
  if (lfd_ >= 0) ::close(lfd_);
}

bool IpcServer::listen(int port, std::string &err) {
  lfd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (lfd_ < 0) {
    err = std::string("ipc socket: ") + strerror(errno);
    return false;
  }
  int one = 1;
  setsockopt(lfd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_ANY);  // inside the container netns; docker publishes 127.0.0.1 only
  a.sin_port = htons((uint16_t)port);
  if (bind(lfd_, (struct sockaddr *)&a, sizeof a) != 0 || ::listen(lfd_, 4) != 0) {
    err = "ipc bind/listen :" + std::to_string(port) + ": " + strerror(errno);
    return false;
  }
  return true;
}

bool IpcServer::on_accept() {
  struct sockaddr_in peer;
  socklen_t len = sizeof peer;
  int fd = accept4(lfd_, (struct sockaddr *)&peer, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
  if (fd < 0) return false;
  char host[INET_ADDRSTRLEN] = "?";
  inet_ntop(AF_INET, &peer.sin_addr, host, sizeof host);
  if (cfd_ >= 0) {
    ALOG_W("ipc: second client %s:%d refused (one client at a time)", host, ntohs(peer.sin_port));
    stats().ipcRejectedSecond++;
    ::close(fd);
    return false;
  }
  cfd_ = fd;
  buf_.clear();
  stats().ipcAccepted++;
  ALOG_I("ipc: client %s:%d connected", host, ntohs(peer.sin_port));
  return true;
}

void IpcServer::on_readable(std::vector<std::string> &lines) {
  char tmp[65536];
  for (;;) {
    ssize_t n = recv(cfd_, tmp, sizeof tmp, MSG_DONTWAIT);
    if (n > 0) {
      buf_.append(tmp, (size_t)n);
      size_t start = 0, nl;
      while ((nl = buf_.find('\n', start)) != std::string::npos) {
        lines.emplace_back(buf_, start, nl - start);
        start = nl + 1;
      }
      buf_.erase(0, start);
      if (buf_.size() > kMaxIpcLine) {
        stats().ipcLineTooLong++;
        close_client("line longer than 1 MiB");
        return;
      }
      continue;
    }
    if (n == 0) {
      close_client("EOF");
      return;
    }
    if (errno == EINTR) continue;
    if (errno != EAGAIN && errno != EWOULDBLOCK) close_client(strerror(errno));
    return;
  }
}

void IpcServer::close_client(const char *why) {
  if (cfd_ < 0) return;
  ALOG_I("ipc: client closed (%s)", why);
  ::close(cfd_);
  cfd_ = -1;
  buf_.clear();
  out_.clear();
}

bool IpcServer::send_line(const std::string &line) {
  if (cfd_ < 0) return false;
  out_ += line;
  flush();
  return true;
}

void IpcServer::flush() {
  while (cfd_ >= 0 && !out_.empty()) {
    ssize_t n = send(cfd_, out_.data(), out_.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n > 0) {
      out_.erase(0, (size_t)n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) close_client(strerror(errno));
    return;
  }
}

}  // namespace agent
