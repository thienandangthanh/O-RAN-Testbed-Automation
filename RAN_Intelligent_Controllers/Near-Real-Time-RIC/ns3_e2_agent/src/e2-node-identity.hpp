// E2 node identity of an ns-3 node (EN-DC scenario, plan R-3): the Global E2 Node ID and the X2 E2 node components
// the E2 Setup Request carries.
//   gnb -> Global en-gNB ID: PLMN + 32-bit gNB ID (= cellId); one served TDD NR cell, NR Cell Identity =
//          gNB ID || cell part 1, PCI = cellId.
//   enb -> Global eNB ID: PLMN + 20-bit macro eNB ID (= cellId); one served FDD E-UTRA cell, E-UTRAN Cell Identity =
//          macro eNB ID || cell 1, PCI = cellId.
// Each X2 component names one neighbour (E2AP v03.00 §9.2.32) and carries, per §9.2.27, this node's EN-DC X2 SETUP
// REQUEST as the request part and the neighbour's EN-DC X2 SETUP RESPONSE as the response part (3GPP TS 36.423
// §9.1.2.31, §9.1.2.32), both whole APER X2AP-PDUs built by libx2ap_codec. A neighbour's IDs follow the same rule
// (gNB ID = macro eNB ID = its cellId).
#ifndef NS3_E2_AGENT_E2_NODE_IDENTITY_HPP
#define NS3_E2_AGENT_E2_NODE_IDENTITY_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "agent-config.hpp"
#include "asn-util.hpp"

extern "C" {
#include "E2nodeComponentID.h"
#include "GlobalE2node-ID.h"
}

namespace agent {

// Served-cell constants (plan R-3; standards ledger of the identity phase).
constexpr uint8_t kNrCellPart = 1;           // NR Cell Identity = gNB ID (32 bits) || 4-bit cell part
constexpr long kNrArfcn = 633333;            // 3.5 GHz, the ns-3 mmWave carrier (scenario-zero centerFrequency)
constexpr long kNrBand = 78;                 // n78 (TDD)
constexpr long kNrScsIndex = 2;              // NRSCS scs60: ns-3 MmWavePhyMacCommon Numerology default 2 (60 kHz)
constexpr long kNrNrbIndex = 2;              // NRNRB nrb24: 20 MHz at 60 kHz SCS (3GPP TS 38.101-1 Table 5.3.2-1)
constexpr int kSsbScsIndex = 1;              // MTC ssbSubcarrierSpacing kHz30: the n78 SSB numerology
constexpr int kSmtcPeriodSf = 20, kSmtcOffsetSf = 0, kSmtcDurationSf = 1;  // SSB timing of the MTC
constexpr uint16_t kConfiguredTac = 0x0001;  // Configured TAC (2 octets); no 5GS-TAC: no 5GS service in EN-DC
constexpr uint8_t kEutraCellPart = 1;        // E-UTRAN Cell Identity = macro eNB ID (20 bits) || 8-bit cell
constexpr long kEutraDlEarfcn = 100, kEutraUlEarfcn = 18100;  // ns-3 LteEnbNetDevice / MmWaveHelper defaults
constexpr long kEutraBandwidthIndex = 5;     // Transmission-Bandwidth bw100 (ns-3 DlBandwidth/UlBandwidth 100 RBs)
constexpr uint16_t kEutraTac = 0x0001;

struct X2Component {
  bool peerIsEnGnb = false;  // the neighbour's Global ID choice in E2nodeComponentInterfaceX2
  uint32_t peerId = 0;       // its gNB ID or macro eNB ID
  Bytes requestPart;         // this node's ENDCX2SetupRequest
  Bytes responsePart;        // the neighbour's ENDCX2SetupResponse
};

// One component per cfg.x2Peers entry. False with err on an ID outside its range or a codec failure.
bool build_x2_components(const Config &cfg, std::vector<X2Component> &out, std::string &err);

// Fills an empty GlobalE2node_ID with the node's Global en-gNB ID (gnb) or Global eNB ID (enb).
bool fill_global_e2node_id(const Config &cfg, GlobalE2node_ID_t &g, std::string &err);

// The neighbour's Global ID as an E2nodeComponentID of interface type X2 (e2nodeComponentInterfaceTypeX2).
bool fill_x2_component_id(const Config &cfg, const X2Component &c, E2nodeComponentID_t &id, std::string &err);

}  // namespace agent

#endif
