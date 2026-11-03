// Loopback check that SctpAssociation sends every message with SCTP PPID 70
// (E2AP, O-RAN E2GAP v08.00 §6.1). A one-to-one SCTP listener on 127.0.0.1
// reads each message with SCTP_RCVINFO and checks rcv_ppid.
// Built as the sctp-ppid-loopback-test target (CMakeLists.txt) and installed in the image.
// Exit 0 = every message carried PPID 70; 1 = a wrong PPID; 2 = setup failure.
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sctp-association.hpp"

namespace {

int listen_loopback(int &port) {
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  if (fd < 0) return -1;
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 1) != 0) return -1;
  socklen_t len = sizeof a;
  getsockname(fd, (struct sockaddr *)&a, &len);
  port = ntohs(a.sin_port);
  return fd;
}

// One message's PPID from SCTP_RCVINFO, or -1.
long recv_ppid(int fd) {
  char buf[4096];
  char cbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
  struct iovec iov = {buf, sizeof buf};
  struct msghdr mh;
  memset(&mh, 0, sizeof mh);
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  mh.msg_control = cbuf;
  mh.msg_controllen = sizeof cbuf;
  struct pollfd p = {fd, POLLIN, 0};
  if (poll(&p, 1, 2000) <= 0 || recvmsg(fd, &mh, 0) <= 0) return -1;
  for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
    if (c->cmsg_level == IPPROTO_SCTP && c->cmsg_type == SCTP_RCVINFO)
      return (long)ntohl(((struct sctp_rcvinfo *)CMSG_DATA(c))->rcv_ppid);
  return -1;
}

}  // namespace

int main() {
  int port = 0;
  int lfd = listen_loopback(port);
  if (lfd < 0) { perror("SCTP listen (is the sctp module loaded?)"); return 2; }
  agent::SctpAssociation a;
  std::string err;
  if (!a.start_connect("127.0.0.1", port, 0, err)) { fprintf(stderr, "%s\n", err.c_str()); return 2; }
  int sfd = accept(lfd, nullptr, nullptr);
  int one = 1;
  if (sfd < 0 || setsockopt(sfd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &one, sizeof one) != 0) { perror("accept"); return 2; }
  struct pollfd p = {a.fd(), POLLOUT, 0};
  poll(&p, 1, 2000);
  if (!a.finish_connect(err)) { fprintf(stderr, "%s\n", err.c_str()); return 2; }
  int bad = 0;
  for (int i = 0; i < 3; i++) {
    agent::Bytes msg(16 + i, (uint8_t)i);
    if (a.send(msg, err) != agent::SctpAssociation::SendResult::Sent) { fprintf(stderr, "send: %s\n", err.c_str()); return 2; }
    long ppid = recv_ppid(sfd);
    printf("message %d ppid %ld\n", i, ppid);
    if (ppid != 70) bad++;
  }
  close(sfd);
  close(lfd);
  printf(bad ? "FAIL\n" : "PASS\n");
  return bad ? 1 : 0;
}
