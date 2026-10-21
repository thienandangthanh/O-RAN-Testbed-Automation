// Active RIC subscriptions of this E2 node. Starts empty on every process
// start (crash-only design: a restart means a fresh E2 setup and new
// subscriptions). Option A: every sample is forwarded under every entry.
#ifndef NS3_E2_AGENT_SUBSCRIPTION_TABLE_HPP
#define NS3_E2_AGENT_SUBSCRIPTION_TABLE_HPP

#include <cstddef>
#include <vector>

namespace agent {

struct Subscription {
  long requestorId = 0;
  long instanceId = 0;
  long ranFuncId = 0;
  std::vector<long> actionIds;  // all admitted actions
  long actionId = 0;            // lowest admitted action: carries the indications
  long nextSn = 0;              // RICindicationSN, 0..65535, wraps
};

class SubscriptionTable {
 public:
  // Adds the entry; an existing (requestorId, instanceId) is replaced. Returns true if replaced.
  bool add_or_replace(const Subscription &s);
  // Removes (requestorId, instanceId); idempotent. Returns true if an entry was removed.
  bool remove(long requestorId, long instanceId);
  std::vector<Subscription> &all() { return subs_; }
  size_t size() const { return subs_.size(); }

 private:
  std::vector<Subscription> subs_;
};

}  // namespace agent

#endif
