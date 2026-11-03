// Admission of a RIC subscription to the KPM RAN function against ns-3's
// indication period T (E2_INDICATION_PERIOD_MS).
//
// E2SM-KPM v03.00: the event trigger (Format 1) carries the reporting period P
// (7.3.2, 8.2.1.1.1); each action definition carries the granularity period G,
// the collection interval of one measurement record (8.2.1.2). ns-3 produces one
// sample per T, so the agent serves exactly G = T and any P that is a whole
// multiple of T: one RIC INDICATION per P carrying P / T records.
//
// E2AP v03.00 answers:
//   - P not a multiple of T (or an event trigger that is not a decodable KPM
//     Format 1): the event trigger covers the whole subscription, so the whole
//     subscription fails: RIC SUBSCRIPTION FAILURE, cause ricRequest /
//     eventTriggerNotSupported (8.2.1.4; 9.2.1 "Requested event trigger
//     definition or modification not supported").
//   - P / T above E2_MAX_REPORT_RECORDS: the period is again the event
//     trigger's, so the whole subscription fails: RIC SUBSCRIPTION FAILURE,
//     cause ricRequest / function-resource-limit (9.2.1 "Function Resource
//     Limit": the RAN function lacks the resources to serve the request; here
//     the samples to buffer and the records of one indication). Checked before
//     anything is buffered.
//   - An action that is not REPORT, has no or an undecodable KPM action
//     definition, or a granularity G != T: that action is not admitted with
//     ricRequest / action-not-supported (9.2.1) in the RIC SUBSCRIPTION RESPONSE
//     that admits the others; with no action left, RIC SUBSCRIPTION FAILURE with
//     the same cause.
#ifndef NS3_E2_AGENT_KPM_SUBSCRIPTION_ADMISSION_HPP
#define NS3_E2_AGENT_KPM_SUBSCRIPTION_ADMISSION_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "e2ap-inbound.hpp"

namespace agent {

struct KpmAdmission {
  bool refused = false;          // answer with RIC SUBSCRIPTION FAILURE
  long refusalCause = -1;        // its CauseRICrequest value
  std::string reason;            // human-readable, for the log
  unsigned long reportingPeriodMs = 0;  // P (when the event trigger decoded)
  long samplesPerReport = 0;            // P / T for an admitted subscription
  std::vector<long> admitted;                      // action IDs, request order
  std::vector<std::pair<long, long>> notAdmitted;  // (action ID, CauseRICrequest), request order
};

// E2SM-KPM-EventTriggerDefinition Format 1 -> reportingPeriod (ms). Clean APER
// decode required. False + err otherwise.
bool decode_kpm_reporting_period(const std::vector<uint8_t> &trigger, unsigned long &periodMs, std::string &err);

// E2SM-KPM-ActionDefinition (any of Formats 1-5) -> granulPeriod (ms) and the
// format number. Formats 2, 4 and 5 carry it in their Format 1 subscription info.
bool decode_kpm_granularity(const std::vector<uint8_t> &actionDefinition, unsigned long &granulMs, int &format,
                            std::string &err);

// Decides the answer to a decoded RICsubscriptionRequest for T = indicationPeriodMs
// and at most maxReportRecords samples (measData items) per report.
KpmAdmission admit_kpm_subscription(const InboundPdu &request, long indicationPeriodMs, long maxReportRecords);

}  // namespace agent

#endif
