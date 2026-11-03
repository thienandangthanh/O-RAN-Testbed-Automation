// KPM subscription admission (see kpm-subscription-admission.hpp).
#include "kpm-subscription-admission.hpp"

#include "asn-util.hpp"

extern "C" {
#include "CauseRICrequest.h"
#include "E2SM-KPM-ActionDefinition-Format1.h"
#include "E2SM-KPM-ActionDefinition-Format2.h"
#include "E2SM-KPM-ActionDefinition-Format3.h"
#include "E2SM-KPM-ActionDefinition-Format4.h"
#include "E2SM-KPM-ActionDefinition-Format5.h"
#include "E2SM-KPM-ActionDefinition.h"
#include "E2SM-KPM-EventTriggerDefinition-Format1.h"
#include "E2SM-KPM-EventTriggerDefinition.h"
#include "RICactionType.h"
}

namespace agent {

bool decode_kpm_reporting_period(const std::vector<uint8_t> &trigger, unsigned long &periodMs, std::string &err) {
  void *p = nullptr;
  if (trigger.empty()) {
    err = "empty event trigger";
    return false;
  }
  if (!aper_decode_clean(&asn_DEF_E2SM_KPM_EventTriggerDefinition, &p, trigger.data(), trigger.size(), err)) {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_EventTriggerDefinition, p);
    err = "E2SM-KPM-EventTriggerDefinition: " + err;
    return false;
  }
  auto *t = (E2SM_KPM_EventTriggerDefinition_t *)p;
  bool ok = t->eventDefinition_formats.present ==
                E2SM_KPM_EventTriggerDefinition__eventDefinition_formats_PR_eventDefinition_Format1 &&
            t->eventDefinition_formats.choice.eventDefinition_Format1 != nullptr;
  if (ok) periodMs = t->eventDefinition_formats.choice.eventDefinition_Format1->reportingPeriod;
  else err = "E2SM-KPM-EventTriggerDefinition is not Format 1";
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_EventTriggerDefinition, p);
  return ok;
}

bool decode_kpm_granularity(const std::vector<uint8_t> &def, unsigned long &granulMs, int &format, std::string &err) {
  void *p = nullptr;
  if (def.empty()) {
    err = "empty action definition";
    return false;
  }
  if (!aper_decode_clean(&asn_DEF_E2SM_KPM_ActionDefinition, &p, def.data(), def.size(), err)) {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, p);
    err = "E2SM-KPM-ActionDefinition: " + err;
    return false;
  }
  const auto &f = ((E2SM_KPM_ActionDefinition_t *)p)->actionDefinition_formats;
  const auto &c = f.choice;
  bool ok = true;
  switch (f.present) {
    case E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format1:
      format = 1;
      granulMs = c.actionDefinition_Format1->granulPeriod;
      break;
    case E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format2:
      format = 2;
      granulMs = c.actionDefinition_Format2->subscriptInfo.granulPeriod;
      break;
    case E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format3:
      format = 3;
      granulMs = c.actionDefinition_Format3->granulPeriod;
      break;
    case E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format4:
      format = 4;
      granulMs = c.actionDefinition_Format4->subscriptionInfo.granulPeriod;
      break;
    case E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format5:
      format = 5;
      granulMs = c.actionDefinition_Format5->subscriptionInfo.granulPeriod;
      break;
    default:
      ok = false;
      err = "E2SM-KPM-ActionDefinition has no known format";
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, p);
  return ok;
}

KpmAdmission admit_kpm_subscription(const InboundPdu &r, long indicationPeriodMs, long maxReportRecords) {
  KpmAdmission a;
  const unsigned long t = (unsigned long)indicationPeriodMs;
  std::string err;
  if (!decode_kpm_reporting_period(r.eventTrigger, a.reportingPeriodMs, err)) {
    a.refused = true;
    a.refusalCause = CauseRICrequest_eventTriggerNotSupported;
    a.reason = err;
    return a;
  }
  if (a.reportingPeriodMs == 0 || a.reportingPeriodMs % t != 0) {
    a.refused = true;
    a.refusalCause = CauseRICrequest_eventTriggerNotSupported;
    a.reason = "reporting period " + std::to_string(a.reportingPeriodMs) + " ms is not a multiple of T = " +
               std::to_string(t) + " ms";
    return a;
  }
  // E2AP v03.01 9.2.1 "Function Resource Limit": the whole subscription fails,
  // before a sample is buffered for it.
  if (a.reportingPeriodMs / t > (unsigned long)maxReportRecords) {
    a.refused = true;
    a.refusalCause = CauseRICrequest_function_resource_limit;
    a.reason = "reporting period " + std::to_string(a.reportingPeriodMs) + " ms needs " +
               std::to_string(a.reportingPeriodMs / t) + " records per report > E2_MAX_REPORT_RECORDS=" +
               std::to_string(maxReportRecords);
    return a;
  }
  a.samplesPerReport = (long)(a.reportingPeriodMs / t);

  std::string why;  // reasons of the not-admitted actions, for the log
  for (size_t i = 0; i < r.actionIds.size(); i++) {
    const long id = r.actionIds[i];
    std::string no;
    unsigned long g = 0;
    int fmt = 0;
    if (r.actionTypes[i] != RICactionType_report) no = "type " + std::to_string(r.actionTypes[i]) + " is not REPORT";
    else if (!r.actionHasDefinition[i]) no = "no action definition";
    else if (!decode_kpm_granularity(r.actionDefinitions[i], g, fmt, err)) no = err;
    else if (g != t)
      no = "Format " + std::to_string(fmt) + " granularity " + std::to_string(g) + " ms != T = " + std::to_string(t) +
           " ms";
    if (no.empty()) {
      a.admitted.push_back(id);
      continue;
    }
    a.notAdmitted.emplace_back(id, (long)CauseRICrequest_action_not_supported);
    why += (why.empty() ? "" : "; ") + ("action " + std::to_string(id) + ": " + no);
  }
  a.reason = why;
  if (a.admitted.empty()) {
    a.refused = true;
    a.refusalCause = CauseRICrequest_action_not_supported;
    a.reason = r.actionIds.empty() ? "no action to admit" : "no action admitted (" + why + ")";
  }
  return a;
}

}  // namespace agent
