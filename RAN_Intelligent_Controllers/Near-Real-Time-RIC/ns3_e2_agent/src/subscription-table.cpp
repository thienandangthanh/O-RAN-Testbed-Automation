// Subscription table (see subscription-table.hpp).
#include "subscription-table.hpp"

#include <algorithm>

namespace agent {

bool SubscriptionTable::add_or_replace(const Subscription &s) {
  for (Subscription &e : subs_)
    if (e.requestorId == s.requestorId && e.instanceId == s.instanceId) {
      e = s;
      return true;
    }
  subs_.push_back(s);
  return false;
}

bool SubscriptionTable::remove(long requestorId, long instanceId) {
  auto it = std::remove_if(subs_.begin(), subs_.end(), [&](const Subscription &e) {
    return e.requestorId == requestorId && e.instanceId == instanceId;
  });
  bool removed = it != subs_.end();
  subs_.erase(it, subs_.end());
  return removed;
}

}  // namespace agent
