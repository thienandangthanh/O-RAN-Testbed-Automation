// E2SM-KPM indication message formats 1 and 2 (see kpm-encoder.hpp).
#include "kpm-encoder.hpp"

#include <cstdlib>

extern "C" {
#include "E2SM-KPM-IndicationMessage-Format1.h"
#include "E2SM-KPM-IndicationMessage-Format2.h"
#include "E2SM-KPM-IndicationMessage.h"
#include "LabelInfoItem.h"
#include "MatchingCondItem.h"
#include "MatchingUEidItem.h"
#include "MatchingUEidList.h"
#include "MeasurementCondUEidItem.h"
#include "MeasurementDataItem.h"
#include "MeasurementInfoItem.h"
#include "MeasurementInfoList.h"
#include "MeasurementLabel.h"
#include "MeasurementRecordItem.h"
#include "E2SM-COMMON-IEs_GlobalENB-ID.h"
#include "UEID-EN-GNB.h"
#include "UEID-ENB.h"
#include "UEID.h"
}

namespace agent {

namespace {

MeasurementRecordItem_t *record(const MeasValue &v) {
  auto *r = (MeasurementRecordItem_t *)calloc(1, sizeof(MeasurementRecordItem_t));
  switch (v.kind) {
    case MeasValue::Integer:
      r->present = MeasurementRecordItem_PR_integer;
      r->choice.integer = v.integer;
      break;
    case MeasValue::Real:
      r->present = MeasurementRecordItem_PR_real;
      r->choice.real = v.real;
      break;
    default:
      r->present = MeasurementRecordItem_PR_noValue;
      r->choice.noValue = 0;
  }
  return r;
}

MeasurementLabel_t *no_label() {
  auto *l = (MeasurementLabel_t *)calloc(1, sizeof(MeasurementLabel_t));
  l->noLabel = (long *)calloc(1, sizeof(long));
  *l->noLabel = MeasurementLabel__noLabel_true;
  return l;
}

// BIT STRING of `bits` bits holding `value` right-aligned, stored left-aligned.
void set_bits(BIT_STRING_t *b, uint32_t value, int bits) {
  int bytes = (bits + 7) / 8;
  int unused = bytes * 8 - bits;
  uint32_t v = value << unused;
  b->buf = (uint8_t *)calloc(1, (size_t)bytes);
  b->size = (size_t)bytes;
  b->bits_unused = unused;
  for (int i = 0; i < bytes; i++) b->buf[i] = (uint8_t)(v >> (8 * (bytes - 1 - i)));
}

// Refuses UE IDs whose values do not fit their ASN.1 types.
bool check_ue_id(const KpmUeId &u, std::string &err) {
  if (u.mEnbUeX2apId > kMaxEnbUeX2apId) {
    err = "format2: m-eNB-UE-X2AP-ID " + std::to_string(u.mEnbUeX2apId) + " outside 0..4095";
    return false;
  }
  if (u.choice == KpmUeId::Choice::EnGnb && u.macroEnbId > kMaxMacroEnbId) {
    err = "format2: macro eNB ID " + std::to_string(u.macroEnbId) + " wider than 20 bits";
    return false;
  }
  return true;
}

MatchingUEidItem_t *ue_id(const KpmUeId &u, const std::array<uint8_t, 3> &plmn) {
  auto *it = (MatchingUEidItem_t *)calloc(1, sizeof(MatchingUEidItem_t));
  if (u.choice == KpmUeId::Choice::EnGnb) {
    auto *en = (UEID_EN_GNB_t *)calloc(1, sizeof(UEID_EN_GNB_t));
    it->ueID.present = UEID_PR_en_gNB_UEID;
    it->ueID.choice.en_gNB_UEID = en;
    en->m_eNB_UE_X2AP_ID = (ENB_UE_X2AP_ID_t)u.mEnbUeX2apId;
    OCTET_STRING_fromBuf(&en->globalENB_ID.pLMNIdentity, (const char *)plmn.data(), 3);
    en->globalENB_ID.eNB_ID.present = E2SM_COMMON_IEs_ENB_ID_PR_macro_eNB_ID;
    set_bits(&en->globalENB_ID.eNB_ID.choice.macro_eNB_ID, u.macroEnbId, 20);
  } else {
    auto *enb = (UEID_ENB_t *)calloc(1, sizeof(UEID_ENB_t));
    it->ueID.present = UEID_PR_eNB_UEID;
    it->ueID.choice.eNB_UEID = enb;
    enb->mME_UE_S1AP_ID = (MME_UE_S1AP_ID_t)u.mmeUeS1apId;
    const uint8_t group[2] = {(uint8_t)(kGummeiMmeGroupId >> 8), (uint8_t)kGummeiMmeGroupId};
    OCTET_STRING_fromBuf(&enb->gUMMEI.pLMN_Identity, (const char *)plmn.data(), 3);
    OCTET_STRING_fromBuf(&enb->gUMMEI.mME_Group_ID, (const char *)group, 2);
    OCTET_STRING_fromBuf(&enb->gUMMEI.mME_Code, (const char *)&kGummeiMmeCode, 1);
    enb->m_eNB_UE_X2AP_ID = (ENB_UE_X2AP_ID_t *)calloc(1, sizeof(ENB_UE_X2AP_ID_t));
    *enb->m_eNB_UE_X2AP_ID = (ENB_UE_X2AP_ID_t)u.mEnbUeX2apId;
    // globalENB-ID stays absent: it is reported only by an SeNB.
  }
  return it;
}

unsigned long *granul(unsigned long ms) {
  auto *g = (unsigned long *)calloc(1, sizeof(unsigned long));
  *g = ms < 1 ? 1 : ms;
  return g;
}

bool encode_message(E2SM_KPM_IndicationMessage_t *m, Bytes &out, std::string &err) {
  bool ok = aper_encode(&asn_DEF_E2SM_KPM_IndicationMessage, m, out, err);
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, m);
  return ok;
}

}  // namespace

bool encode_format1(const std::vector<std::vector<MeasValue>> &periods, const std::vector<MetricRow> &rows,
                    unsigned long granulPeriodMs, Bytes &out, std::string &err) {
  if (periods.empty() || rows.empty()) {
    err = "format1: needs at least one period and one metric";
    return false;
  }
  for (const auto &records : periods)
    if (records.size() != rows.size()) {
      err = "format1: record count != cell list length";
      return false;
    }
  auto *m = (E2SM_KPM_IndicationMessage_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_t));
  auto *f1 = (E2SM_KPM_IndicationMessage_Format1_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_Format1_t));
  m->indicationMessage_formats.present = E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;
  m->indicationMessage_formats.choice.indicationMessage_Format1 = f1;

  for (const auto &records : periods) {
    auto *item = (MeasurementDataItem_t *)calloc(1, sizeof(MeasurementDataItem_t));
    for (const MeasValue &v : records) ASN_SEQUENCE_ADD(&item->measRecord.list, record(v));
    ASN_SEQUENCE_ADD(&f1->measData.list, item);  // incompleteFlag stays absent
  }

  f1->measInfoList = (MeasurementInfoList *)calloc(1, sizeof(MeasurementInfoList_t));
  for (const MetricRow &r : rows) {
    auto *info = (MeasurementInfoItem_t *)calloc(1, sizeof(MeasurementInfoItem_t));
    info->measType.present = MeasurementType_PR_measID;
    info->measType.choice.measID = r.measId;
    auto *lab = (LabelInfoItem_t *)calloc(1, sizeof(LabelInfoItem_t));
    MeasurementLabel_t *nl = no_label();
    lab->measLabel = *nl;  // LabelInfoItem embeds the label by value
    free(nl);
    ASN_SEQUENCE_ADD(&info->labelInfoList.list, lab);
    ASN_SEQUENCE_ADD(&f1->measInfoList->list, info);
  }
  f1->granulPeriod = granul(granulPeriodMs);
  return encode_message(m, out, err);
}

bool encode_format2(const std::vector<std::vector<std::vector<MeasValue>>> &periods,
                    const std::vector<KpmUeId> &ueIds, const std::vector<MetricRow> &rows,
                    const std::array<uint8_t, 3> &plmn, bool withUeIds, unsigned long granulPeriodMs, Bytes &out,
                    std::string &err) {
  if (periods.empty() || ueIds.empty() || rows.empty()) {
    err = "format2: needs at least one period, one UE and one metric";
    return false;
  }
  if (withUeIds)
    for (const KpmUeId &u : ueIds)
      if (!check_ue_id(u, err)) return false;
  for (const auto &perUe : periods) {
    if (perUe.size() != ueIds.size()) {
      err = "format2: UE count differs between periods";
      return false;
    }
    for (const auto &u : perUe)
      if (u.size() != rows.size()) {
        err = "format2: UE record count != UE list length";
        return false;
      }
  }
  auto *m = (E2SM_KPM_IndicationMessage_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_t));
  auto *f2 = (E2SM_KPM_IndicationMessage_Format2_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_Format2_t));
  m->indicationMessage_formats.present = E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format2;
  m->indicationMessage_formats.choice.indicationMessage_Format2 = f2;

  // kpimon indexes the records of an item as (ue + metric * nUe).
  for (const auto &perUe : periods) {
    auto *item = (MeasurementDataItem_t *)calloc(1, sizeof(MeasurementDataItem_t));
    for (size_t mi = 0; mi < rows.size(); mi++)
      for (size_t ui = 0; ui < perUe.size(); ui++) ASN_SEQUENCE_ADD(&item->measRecord.list, record(perUe[ui][mi]));
    ASN_SEQUENCE_ADD(&f2->measData.list, item);
  }

  for (const MetricRow &r : rows) {
    auto *c = (MeasurementCondUEidItem_t *)calloc(1, sizeof(MeasurementCondUEidItem_t));
    c->measType.present = MeasurementType_PR_measID;
    c->measType.choice.measID = r.measId;
    auto *mc = (MatchingCondItem_t *)calloc(1, sizeof(MatchingCondItem_t));
    mc->matchingCondChoice.present = MatchingCondItem_Choice_PR_measLabel;
    mc->matchingCondChoice.choice.measLabel = no_label();
    ASN_SEQUENCE_ADD(&c->matchingCond.list, mc);
    if (withUeIds) {
      c->matchingUEidList = (MatchingUEidList *)calloc(1, sizeof(MatchingUEidList_t));
      for (const KpmUeId &u : ueIds) ASN_SEQUENCE_ADD(&c->matchingUEidList->list, ue_id(u, plmn));
    }
    // matchingUEidPerGP is a v3 extension addition: never set.
    ASN_SEQUENCE_ADD(&f2->measCondUEidList.list, c);
  }
  f2->granulPeriod = granul(granulPeriodMs);
  return encode_message(m, out, err);
}

}  // namespace agent
