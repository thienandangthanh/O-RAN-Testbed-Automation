// Agent-owned E2SM-KPM encoders, built on NIST's KPM v3 asn1c (e2sim/asn1c).
// Rule: no KPM v3 extension addition is ever set, so kpimon's v2 decoder
// (plus SIZE(8) TimeStamp) reads the same structures.
#ifndef NS3_E2_AGENT_KPM_ENCODER_HPP
#define NS3_E2_AGENT_KPM_ENCODER_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "asn-util.hpp"
#include "metric-map.hpp"

namespace agent {

struct RanFunctionNames {
  std::string shortName = "ORAN-E2SM-KPM";
  std::string oid;
  std::string description;
  long instance = 1;
};

// E2SM-KPM-RANfunction-Description: event trigger style 1 (periodic) and two
// report styles: {1: action format 1 -> message format 1, cell list} and
// {3: action format 3 -> message format 2, UE list}; every item has measName + measID.
bool encode_ran_function_description(const RanFunctionNames &names, const std::vector<MetricRow> &cell,
                                     const std::vector<MetricRow> &ue, Bytes &out, std::string &err);

// RFC 5905 NTP-64 (be32 seconds since 1900, be32 fraction) of a Unix epoch time in ms.
std::array<uint8_t, 8> ntp64_from_unix_ms(int64_t unixMs);

// Header identity strings. senderType is PrintableString (SIZE(0..8)) in KPM v3,
// so the design's "simulator" (9 characters) cannot be encoded; "ns-3-sim" is used.
constexpr const char *kSenderType = "ns-3-sim";
constexpr const char *kVendorName = "ns-O-RAN";

// E2SM-KPM-IndicationHeader format 1 with an 8-octet colletStartTime.
bool encode_indication_header(const std::array<uint8_t, 8> &ts, const std::string &senderName,
                              const std::string &senderType, const std::string &vendorName, Bytes &out,
                              std::string &err);

// IndicationMessage format 1: one measData item whose records follow the cell
// list order; measInfoList carries each measID with noLabel; no incompleteFlag.
bool encode_format1(const std::vector<MeasValue> &records, const std::vector<MetricRow> &rows,
                    unsigned long granulPeriodMs, Bytes &out, std::string &err);

// Fixed GUAMI used in every gNB-UEID (PLMN = the node's PLMN).
struct Guami {
  std::array<uint8_t, 3> plmn{};
  uint8_t amfRegionId = 1;   // BIT STRING (SIZE(8))
  uint16_t amfSetId = 1;     // BIT STRING (SIZE(10))
  uint8_t amfPointer = 1;    // BIT STRING (SIZE(6))
};

// IndicationMessage format 2, metric-major: records[m * nUe + u] = perUe[u][m].
// measCondUEidList has one item per UE-list metric (measID, noLabel and, when
// withUeIds, one gNB-UEID per UE with amf-UE-NGAP-ID = imsi).
bool encode_format2(const std::vector<std::vector<MeasValue>> &perUe, const std::vector<uint64_t> &imsis,
                    const std::vector<MetricRow> &rows, const Guami &guami, bool withUeIds,
                    unsigned long granulPeriodMs, Bytes &out, std::string &err);

}  // namespace agent

#endif
