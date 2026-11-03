// Active RIC subscriptions of this E2 node. Starts empty on every process
// start (crash-only design: a restart means a fresh E2 setup and new
// subscriptions). Every sample goes to every entry, which reports once per
// samplesPerReport (P / T) consecutive samples.
#ifndef NS3_E2_AGENT_SUBSCRIPTION_TABLE_HPP
#define NS3_E2_AGENT_SUBSCRIPTION_TABLE_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "metric-map.hpp"

namespace agent {

struct Subscription {
  long requestorId = 0;
  long instanceId = 0;
  long ranFuncId = 0;
  std::vector<long> actionIds;  // all admitted actions
  long actionId = 0;            // lowest admitted action: carries the indications
  long nextSn = 0;              // RICindicationSN, 0..65535, wraps
  long samplesPerReport = 1;    // P / T: samples per RIC INDICATION report
  std::vector<SampleRecords> window;  // samples of the reporting period in progress
  int64_t lastSeq = -1;               // seq of the last sample seen (-1: none since the last end_periods)
};

// One sample's way through every subscription's reporting period, in samples.
// With one subscription (the testbed: kpimon), or several of the same P seeing
// the same samples: forwarded + gapDiscarded + failed + the change of
// pending_samples() == 1, so over a run samplesIn == forwarded + gapDiscarded +
// failed + unreported (+ the drops before a sample reaches the table).
struct PeriodTally {
  size_t forwarded = 0;     // samples that went out in a report
  size_t gapDiscarded = 0;  // samples of periods restarted by a seq gap
  size_t failed = 0;        // samples of reports that could not be encoded or sent
  uint64_t gaps = 0;        // periods restarted by a seq gap
};

class SubscriptionTable {
 public:
  // Encodes and sends one report of a completed reporting period; false if it
  // could not be encoded or sent.
  using ReportFn = std::function<bool(Subscription &, const std::vector<SampleRecords> &)>;

  // Adds the entry; an existing (requestorId, instanceId) is replaced. Returns true if replaced.
  bool add_or_replace(const Subscription &s);
  // Removes (requestorId, instanceId); idempotent. Returns true if an entry was removed.
  bool remove(long requestorId, long instanceId);
  std::vector<Subscription> &all() { return subs_; }
  size_t size() const { return subs_.size(); }
  // Adds the sample to every subscription's reporting period. A period is
  // aligned to the first sample its subscription sees and holds P / T
  // consecutive samples; a seq gap restarts it (its samples are discarded). A
  // completed period goes to report() and ends whatever report() returns. The
  // counts are the maximum over the subscriptions.
  PeriodTally add_sample(const SampleRecords &r, const ReportFn &report);
  // Samples taken but not yet reported (the longest period in progress).
  size_t pending_samples() const;
  // Ends every period in progress unreported (a new ns-3 run follows, so seq
  // continuity restarts too); returns pending_samples() before.
  size_t end_periods();

 private:
  std::vector<Subscription> subs_;
};

}  // namespace agent

#endif
