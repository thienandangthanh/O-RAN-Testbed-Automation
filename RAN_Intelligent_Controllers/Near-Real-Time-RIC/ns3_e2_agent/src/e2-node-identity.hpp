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
constexpr long kNrBand = 78;                 // n78 (TDD)
constexpr long kNrScsIndex = 2;              // NRSCS scs60: ns-3 MmWavePhyMacCommon Numerology default 2 (60 kHz)
constexpr long kNrNrbIndex = 2;              // NRNRB nrb24: 20 MHz at 60 kHz SCS (3GPP TS 38.101-1 Table 5.3.2-1)
constexpr long kNrNrb = 24;                  // N_RB of nrb24
constexpr long kNrScsArfcnSteps = 4;         // one 60 kHz subcarrier = 4 NR-ARFCN steps of 15 kHz
constexpr int kSsbScsIndex = 1;              // MTC ssbSubcarrierSpacing kHz30: the n78 SSB numerology
constexpr int kSmtcPeriodSf = 20, kSmtcOffsetSf = 0, kSmtcDurationSf = 1;  // SSB timing of the MTC

// NR frequencies of the served cell, as NR-ARFCN N (F = 3000 MHz + 15 kHz * (N - 600000) for 3 to 24.25 GHz;
// 3GPP TS 38.104 Table 5.4.2.1-1). The ns-3 carrier is 3.5 GHz (scenario-zero centerFrequency), 20 MHz wide.
//
// kNrFref: the carrier's RF reference frequency F_REF, 633334 = 3500.010 MHz, the n78 channel-raster point nearest
//   3.5 GHz. n78 has a 15 kHz and a 30 kHz raster; a carrier whose SCS is >= 30 kHz and whose SSB SCS is 30 kHz uses
//   the 30 kHz one, 620000 + 2n up to 653332 (38.104 §5.4.2.3 and Table 5.4.2.3-1). 633333 is off that raster.
//   F_REF is not sent: X2 carries Point A.
// kNrPointA: the X2 NRARFCN, "the absolute frequency position of the reference resource block (Common RB 0) of the
//   carrier. Its lowest subcarrier is also known as Point A" (3GPP TS 36.423 §9.2.106). Subcarrier 0 of CRB 0 is
//   centred on Point A at every numerology (38.211 §4.4.4.3). X2 sends no NR Carrier List (36.423 §9.2.168), so
//   offsetToCarrier is 0 and the carrier's lowest subcarrier is Point A. F_REF maps to subcarrier k = 0 of PRB
//   floor(N_RB / 2) (38.104 Table 5.4.2.2-1), so Point A = F_REF - (24 / 2) * 12 * 4 = F_REF - 576.
// kNrSsbArfcn: the MTC carrierFreq, the frequency of the SS block (3GPP TS 38.331 MeasTiming), placed on n78's
//   synchronization raster: GSCN 7846 = 3000 MHz + (7846 - 7499) * 1.44 MHz = 3499.68 MHz (38.104 Table 5.4.3.1-1;
//   n78 GSCN 7711 to 8051, 38.101-1 Table 5.4.3.3-1), so N = 600000 + (GSCN - 7499) * 96. SS_REF is SSB subcarrier
//   120 of 0..239 (38.104 Table 5.4.3.2-1; 38.211 §7.4.3.1), 2 NR-ARFCN steps each at 30 kHz, so the SSB spans
//   N - 240 to N + 238. It lies inside the carrier (offsetToPointA 26, k_SSB 2).
constexpr long kNrFref = 633334;
constexpr long kNrPointA = kNrFref - (kNrNrb / 2) * 12 * kNrScsArfcnSteps;
constexpr long kSsbGscn = 7846;
constexpr long kNrSsbArfcn = 600000 + (kSsbGscn - 7499) * 96;
static_assert(kNrFref >= 620000 && (kNrFref - 620000) % 2 == 0 && kNrFref <= 653332,
              "F_REF must be on n78's 30 kHz channel raster (38.104 Table 5.4.2.3-1)");
static_assert(kNrSsbArfcn - 240 >= kNrPointA, "the SSB's lowest subcarrier must lie inside the carrier");
static_assert(kNrSsbArfcn + 238 <= kNrPointA + (kNrNrb * 12 - 1) * kNrScsArfcnSteps,
              "the SSB's highest subcarrier must lie inside the carrier");
static_assert(kSsbGscn >= 7711 && kSsbGscn <= 8051, "the SSB GSCN must be in n78's range (38.101-1 Table 5.4.3.3-1)");
static_assert(kNrPointA == 632758 && kNrSsbArfcn == 633312, "the served NR cell's frequencies on the wire");
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
