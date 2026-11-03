// SCTP association to e2term (see sctp-association.hpp).
#include "sctp-association.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "agent-log.hpp"

namespace agent {

namespace {

// Heartbeat every 5 s and at most 3 retransmissions per path and per
// association, so a silently vanished peer is detected in about 20 s.
void set_liveness_options(int fd) {
  struct sctp_paddrparams pp;
  memset(&pp, 0, sizeof pp);
  pp.spp_hbinterval = 5000;
  pp.spp_pathmaxrxt = 3;
  pp.spp_flags = SPP_HB_ENABLE;
  if (setsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &pp, sizeof pp) != 0)
    ALOG_W("SCTP_PEER_ADDR_PARAMS: %s", strerror(errno));
  struct sctp_assocparams ap;
  memset(&ap, 0, sizeof ap);
  ap.sasoc_asocmaxrxt = 3;
  if (setsockopt(fd, IPPROTO_SCTP, SCTP_ASSOCINFO, &ap, sizeof ap) != 0)
    ALOG_W("SCTP_ASSOCINFO: %s", strerror(errno));
}

// E2AP's SCTP Payload Protocol Identifier, assigned by IANA (O-RAN E2GAP
// v08.00 §6.1: "is 70 ... to be used for all deployment configurations").
constexpr uint32_t kE2apPpid = 70;

// Makes every message on this association carry PPID 70 by default.
bool set_default_ppid(int fd, std::string &err) {
  struct sctp_sndinfo si;
  memset(&si, 0, sizeof si);
  si.snd_ppid = htonl(kE2apPpid);
  if (setsockopt(fd, IPPROTO_SCTP, SCTP_DEFAULT_SNDINFO, &si, sizeof si) == 0) return true;
  err = std::string("SCTP_DEFAULT_SNDINFO: ") + strerror(errno);
  return false;
}

}  // namespace

bool SctpAssociation::start_connect(const std::string &addr, int port, int srcPort, std::string &err) {
  close();
  struct addrinfo hints, *res = nullptr;
  memset(&hints, 0, sizeof hints);
  hints.ai_flags = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(addr.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
    err = "bad E2_TERM_ADDR " + addr;
    return false;
  }
  fd_ = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_SCTP);
  if (fd_ < 0) {
    err = std::string("socket: ") + strerror(errno);
    freeaddrinfo(res);
    return false;
  }
  int one = 1;
  setsockopt(fd_, IPPROTO_SCTP, SCTP_NODELAY, &one, sizeof one);
  struct sctp_event_subscribe ev;
  memset(&ev, 0, sizeof ev);
  ev.sctp_association_event = 1;
  ev.sctp_shutdown_event = 1;
  if (setsockopt(fd_, IPPROTO_SCTP, SCTP_EVENTS, &ev, sizeof ev) != 0) ALOG_W("SCTP_EVENTS: %s", strerror(errno));
  set_liveness_options(fd_);
  if (srcPort > 0) {  // fallback mode: NIST's fixed source port
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_storage local;
    memset(&local, 0, sizeof local);
    local.ss_family = (sa_family_t)res->ai_family;
    if (res->ai_family == AF_INET) ((struct sockaddr_in *)&local)->sin_port = htons((uint16_t)srcPort);
    else ((struct sockaddr_in6 *)&local)->sin6_port = htons((uint16_t)srcPort);
    if (bind(fd_, (struct sockaddr *)&local, res->ai_addrlen) != 0) {
      err = std::string("bind source port: ") + strerror(errno);
      freeaddrinfo(res);
      close();
      return false;
    }
  }
  int rc = connect(fd_, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  if (rc != 0 && errno != EINPROGRESS) {
    err = std::string("connect: ") + strerror(errno);
    close();
    return false;
  }
  connecting_ = true;
  return true;
}

bool SctpAssociation::finish_connect(std::string &err) {
  int soerr = 0;
  socklen_t len = sizeof soerr;
  if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0) {
    err = std::string("connect: ") + strerror(soerr ? soerr : errno);
    close();
    return false;
  }
  connecting_ = false;
  set_liveness_options(fd_);  // again, now that the association exists
  // PPID 70 on every message: the socket default if the kernel takes it, else
  // an SCTP_SNDINFO control message per send. A send that cannot carry PPID 70
  // fails (Lost); nothing is ever sent with PPID 0.
  std::string why;
  ppidPerMessage_ = !set_default_ppid(fd_, why);
  if (ppidPerMessage_) ALOG_W("%s; PPID %u set per message", why.c_str(), (unsigned)kE2apPpid);
  return true;
}

bool SctpAssociation::read_messages(std::vector<Bytes> &out, std::string &reason) {
  uint8_t buf[65536];
  for (;;) {
    struct iovec iov = {buf, sizeof buf};
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    ssize_t n = recvmsg(fd_, &mh, MSG_DONTWAIT);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
      if (errno == EINTR) continue;
      reason = std::string("recv: ") + strerror(errno);
      return false;
    }
    if (n == 0) {
      reason = "peer closed the association";
      return false;
    }
    if (mh.msg_flags & MSG_NOTIFICATION) {
      auto *sn = (union sctp_notification *)buf;
      if (sn->sn_header.sn_type == SCTP_SHUTDOWN_EVENT) {
        reason = "SCTP_SHUTDOWN_EVENT";
        return false;
      }
      if (sn->sn_header.sn_type == SCTP_ASSOC_CHANGE) {
        uint16_t st = sn->sn_assoc_change.sac_state;
        if (st == SCTP_COMM_LOST || st == SCTP_SHUTDOWN_COMP || st == SCTP_CANT_STR_ASSOC) {
          reason = st == SCTP_COMM_LOST ? "SCTP_COMM_LOST" : st == SCTP_SHUTDOWN_COMP ? "SCTP_SHUTDOWN_COMP"
                                                                                       : "SCTP_CANT_STR_ASSOC";
          return false;
        }
      }
      continue;
    }
    partial_.insert(partial_.end(), buf, buf + n);
    if (mh.msg_flags & MSG_EOR) {
      out.push_back(std::move(partial_));
      partial_.clear();
    }
  }
}

SctpAssociation::SendResult SctpAssociation::send(const Bytes &msg, std::string &err) {
  for (;;) {
    ssize_t n;
    if (!ppidPerMessage_) {
      n = ::send(fd_, msg.data(), msg.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    } else {
      struct iovec iov = {const_cast<uint8_t *>(msg.data()), msg.size()};
      alignas(struct cmsghdr) char cbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
      memset(cbuf, 0, sizeof cbuf);
      struct msghdr mh;
      memset(&mh, 0, sizeof mh);
      mh.msg_iov = &iov;
      mh.msg_iovlen = 1;
      mh.msg_control = cbuf;
      mh.msg_controllen = sizeof cbuf;
      struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
      c->cmsg_level = IPPROTO_SCTP;
      c->cmsg_type = SCTP_SNDINFO;
      c->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
      auto *si = (struct sctp_sndinfo *)CMSG_DATA(c);
      si->snd_ppid = htonl(kE2apPpid);
      n = ::sendmsg(fd_, &mh, MSG_NOSIGNAL | MSG_DONTWAIT);
    }
    if (n == (ssize_t)msg.size()) return SendResult::Sent;
    if (n >= 0) {
      err = "short SCTP send";
      return SendResult::Lost;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return SendResult::Busy;
    err = std::string("send: ") + strerror(errno);
    return SendResult::Lost;
  }
}

void SctpAssociation::close() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
  connecting_ = false;
  partial_.clear();
}

void SctpAssociation::graceful_close(int timeoutMs) {
  if (fd_ < 0 || connecting_) { close(); return; }
  ::shutdown(fd_, SHUT_WR);  // one-to-one SCTP: sends SHUTDOWN
  char buf[2048];
  for (int waited = 0; waited < timeoutMs; waited += 100) {
    struct pollfd p = {fd_, POLLIN, 0};
    if (::poll(&p, 1, 100) <= 0) continue;
    ssize_t n = ::recv(fd_, buf, sizeof buf, MSG_DONTWAIT);
    if (n == 0) break;  // SHUTDOWN COMPLETE: association ended
    if (n < 0 && errno != EAGAIN && errno != EINTR) break;
  }
  close();
}

std::string SctpAssociation::local_endpoint() const {
  struct sockaddr_storage ss;
  socklen_t len = sizeof ss;
  char host[INET6_ADDRSTRLEN] = "?";
  int port = 0;
  if (fd_ >= 0 && getsockname(fd_, (struct sockaddr *)&ss, &len) == 0) {
    if (ss.ss_family == AF_INET) {
      inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, host, sizeof host);
      port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
    } else {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, host, sizeof host);
      port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    }
  }
  return std::string(host) + ":" + std::to_string(port);
}

}  // namespace agent
