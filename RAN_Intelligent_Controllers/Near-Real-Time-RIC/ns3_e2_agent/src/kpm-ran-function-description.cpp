// E2SM-KPM RAN function description and indication header (see kpm-encoder.hpp).
#include "kpm-encoder.hpp"

#include <cstdlib>
#include <cstring>

extern "C" {
#include "E2SM-KPM-IndicationHeader-Format1.h"
#include "E2SM-KPM-IndicationHeader.h"
#include "E2SM-KPM-RANfunction-Description.h"
#include "MeasurementInfo-Action-Item.h"
#include "RIC-EventTriggerStyle-Item.h"
#include "RIC-ReportStyle-Item.h"
}

namespace agent {

namespace {

// One report style item; measInfo_Action_List = (measName, measID) per row.
RIC_ReportStyle_Item_t *report_style(long type, const char *name, long actFmt, long msgFmt,
                                     const std::vector<MetricRow> &rows) {
  auto *s = (RIC_ReportStyle_Item_t *)calloc(1, sizeof(RIC_ReportStyle_Item_t));
  s->ric_ReportStyle_Type = type;
  set_octets(&s->ric_ReportStyle_Name, name);
  s->ric_ActionFormat_Type = actFmt;
  s->ric_IndicationHeaderFormat_Type = 1;
  s->ric_IndicationMessageFormat_Type = msgFmt;
  for (const MetricRow &r : rows) {
    auto *it = (MeasurementInfo_Action_Item_t *)calloc(1, sizeof(MeasurementInfo_Action_Item_t));
    set_octets(&it->measName, r.kpm);
    it->measID = (MeasurementTypeID_t *)calloc(1, sizeof(MeasurementTypeID_t));
    *it->measID = r.measId;
    // binRangeDef is a v3 extension addition: never set.
    ASN_SEQUENCE_ADD(&s->measInfo_Action_List.list, it);
  }
  return s;
}

}  // namespace

bool encode_ran_function_description(const RanFunctionNames &names, const std::vector<MetricRow> &cell,
                                     const std::vector<MetricRow> &ue, Bytes &out, std::string &err) {
  auto *d = (E2SM_KPM_RANfunction_Description_t *)calloc(1, sizeof(E2SM_KPM_RANfunction_Description_t));
  set_octets(&d->ranFunction_Name.ranFunction_ShortName, names.shortName);
  set_octets(&d->ranFunction_Name.ranFunction_E2SM_OID, names.oid);
  set_octets(&d->ranFunction_Name.ranFunction_Description, names.description);
  d->ranFunction_Name.ranFunction_Instance = (long *)calloc(1, sizeof(long));
  *d->ranFunction_Name.ranFunction_Instance = names.instance;

  d->ric_EventTriggerStyle_List =
      (decltype(d->ric_EventTriggerStyle_List))calloc(1, sizeof(*d->ric_EventTriggerStyle_List));
  auto *ev = (RIC_EventTriggerStyle_Item_t *)calloc(1, sizeof(RIC_EventTriggerStyle_Item_t));
  ev->ric_EventTriggerStyle_Type = 1;
  set_octets(&ev->ric_EventTriggerStyle_Name, "Periodic Report");
  ev->ric_EventTriggerFormat_Type = 1;
  ASN_SEQUENCE_ADD(&d->ric_EventTriggerStyle_List->list, ev);

  d->ric_ReportStyle_List = (decltype(d->ric_ReportStyle_List))calloc(1, sizeof(*d->ric_ReportStyle_List));
  ASN_SEQUENCE_ADD(&d->ric_ReportStyle_List->list, report_style(1, "E2 Node Measurement", 1, 1, cell));
  ASN_SEQUENCE_ADD(&d->ric_ReportStyle_List->list,
                   report_style(3, "Condition-based, UE-level E2 Node Measurement", 3, 2, ue));

  bool ok = aper_encode(&asn_DEF_E2SM_KPM_RANfunction_Description, d, out, err);
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_RANfunction_Description, d);
  return ok;
}

std::array<uint8_t, 8> ntp64_from_unix_ms(int64_t unixMs) {
  if (unixMs < 0) unixMs = 0;
  uint64_t secs = (uint64_t)(unixMs / 1000) + 2208988800ull;  // 1900 -> 1970 offset
  uint64_t frac = ((uint64_t)(unixMs % 1000) << 32) / 1000;
  std::array<uint8_t, 8> b{};
  for (int i = 0; i < 4; i++) {
    b[i] = (uint8_t)(secs >> (24 - 8 * i));
    b[4 + i] = (uint8_t)(frac >> (24 - 8 * i));
  }
  return b;
}

bool encode_indication_header(const std::array<uint8_t, 8> &ts, const std::string &senderName,
                              const std::string &senderType, const std::string &vendorName, Bytes &out,
                              std::string &err) {
  auto *h = (E2SM_KPM_IndicationHeader_t *)calloc(1, sizeof(E2SM_KPM_IndicationHeader_t));
  auto *f1 = (E2SM_KPM_IndicationHeader_Format1_t *)calloc(1, sizeof(E2SM_KPM_IndicationHeader_Format1_t));
  h->indicationHeader_formats.present = E2SM_KPM_IndicationHeader__indicationHeader_formats_PR_indicationHeader_Format1;
  h->indicationHeader_formats.choice.indicationHeader_Format1 = f1;
  OCTET_STRING_fromBuf(&f1->colletStartTime, (const char *)ts.data(), (int)ts.size());
  f1->senderName = new_octets(senderName);
  f1->senderType = new_octets(senderType);
  f1->vendorName = new_octets(vendorName);
  bool ok = aper_encode(&asn_DEF_E2SM_KPM_IndicationHeader, h, out, err);
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationHeader, h);
  return ok;
}

}  // namespace agent
