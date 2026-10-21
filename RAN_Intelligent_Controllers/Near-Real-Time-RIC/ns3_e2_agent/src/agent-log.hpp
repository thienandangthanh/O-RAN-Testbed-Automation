// Human-readable agent log lines go to stderr (docker logs keeps both streams);
// stdout is reserved for the machine-readable JSON stats lines.
#ifndef NS3_E2_AGENT_LOG_HPP
#define NS3_E2_AGENT_LOG_HPP

#include <cstdio>
#include <ctime>
#include <sys/time.h>

namespace agent {

// Writes "<UTC ISO-8601 with ms> <level> <message>" to stderr.
inline void log_prefix(const char *level) {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  struct tm tm;
  gmtime_r(&tv.tv_sec, &tm);
  char buf[32];
  strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
  fprintf(stderr, "%s.%03ldZ ns3-e2-agent %s ", buf, (long)(tv.tv_usec / 1000), level);
}

}  // namespace agent

#define ALOG(level, ...)                 \
  do {                                   \
    agent::log_prefix(level);            \
    fprintf(stderr, __VA_ARGS__);        \
    fputc('\n', stderr);                 \
  } while (0)

#define ALOG_I(...) ALOG("INFO", __VA_ARGS__)
#define ALOG_W(...) ALOG("WARN", __VA_ARGS__)
#define ALOG_E(...) ALOG("ERROR", __VA_ARGS__)

#endif
