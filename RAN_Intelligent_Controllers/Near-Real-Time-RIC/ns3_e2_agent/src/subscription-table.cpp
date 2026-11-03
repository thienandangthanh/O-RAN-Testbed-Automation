// Subscription table (see subscription-table.hpp).
#include "subscription-table.hpp"

#include <algorithm>

#include "agent-log.hpp"

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

PeriodTally SubscriptionTable::add_sample(const SampleRecords &r, const ReportFn &report) {
  PeriodTally t;
  const size_t before = pending_samples();
  for (Subscription &sub : subs_) {
    // A gap right after a completed period discards nothing but still counts.
    if (sub.lastSeq >= 0 && r.seq != sub.lastSeq + 1) {
      ALOG_W("seq %lld after %lld: the reporting period of subscription %ld/%ld restarts (%zu sample(s) discarded)",
             (long long)r.seq, (long long)sub.lastSeq, sub.requestorId, sub.instanceId, sub.window.size());
      t.gaps++;
      t.gapDiscarded = std::max(t.gapDiscarded, sub.window.size());
      sub.window.clear();
    }
    sub.lastSeq = r.seq;
    sub.window.push_back(r);
    if ((long)sub.window.size() < sub.samplesPerReport) continue;
    if (!report(sub, sub.window)) t.failed = std::max(t.failed, sub.window.size());
    sub.window.clear();
  }
  // Exact for one subscription (or several of the same P seeing the same samples).
  // With subscriptions of different P the maxima are only approximate and the
  // difference can go negative, hence the clamp.
  const int64_t fwd = (int64_t)before + 1 - (int64_t)t.gapDiscarded - (int64_t)t.failed - (int64_t)pending_samples();
  t.forwarded = fwd > 0 ? (size_t)fwd : 0;
  return t;
}

size_t SubscriptionTable::pending_samples() const {
  size_t n = 0;
  for (const Subscription &sub : subs_) n = std::max(n, sub.window.size());
  return n;
}

size_t SubscriptionTable::end_periods() {
  size_t n = pending_samples();
  for (Subscription &sub : subs_) {
    sub.window.clear();
    sub.lastSeq = -1;
  }
  return n;
}

}  // namespace agent
