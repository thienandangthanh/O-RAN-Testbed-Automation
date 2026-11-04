// The KPM UE ID of one UE (kpm-encoder.hpp encodes it), kept apart so that a
// sample's records (metric-map.hpp SampleRecords) carry the IDs valid at its seq.
#ifndef NS3_E2_AGENT_KPM_UE_ID_HPP
#define NS3_E2_AGENT_KPM_UE_ID_HPP

#include <cstdint>

namespace agent {

// The UE ID of one UE in a Format 2 message: the alternative of the E2SM
// common UEID CHOICE (NIST's KPM v3 asn1c, UEID.h) for the reporting node's type. An en-gNB reports
// en-gNB-UEID {m-eNB-UE-X2AP-ID, globalENB-ID}; the eNB reports eNB-UEID
// {mME-UE-S1AP-ID, gUMMEI, m-eNB-UE-X2AP-ID} with globalENB-ID absent (it is
// reported only by an SeNB). Every other optional field is absent. The IMSI is
// never encoded as the KPM UE ID: there is no gNB-UEID alternative here.
struct KpmUeId {
  enum class Choice { EnGnb, Enb };
  Choice choice = Choice::EnGnb;
  uint32_t mEnbUeX2apId = 0;  // ENB-UE-X2AP-ID INTEGER (0..4095): the MN's LTE RNTI
  uint32_t macroEnbId = 0;    // en-gNB: globalENB-ID macro eNB ID (20 bits): the MN's cellId
  uint32_t mmeUeS1apId = 0;   // eNB: MME-UE-S1AP-ID INTEGER (0..2^32-1)

  // Equal when they encode the same UEID: the members of the choice only.
  bool operator==(const KpmUeId &o) const {
    if (choice != o.choice || mEnbUeX2apId != o.mEnbUeX2apId) return false;
    return choice == Choice::EnGnb ? macroEnbId == o.macroEnbId : mmeUeS1apId == o.mmeUeS1apId;
  }
};

constexpr uint32_t kMaxEnbUeX2apId = 4095;
constexpr uint32_t kMaxMacroEnbId = (1u << 20) - 1;

}  // namespace agent

#endif
