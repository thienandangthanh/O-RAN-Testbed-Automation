// E2 node identity (see e2-node-identity.hpp).
#include "e2-node-identity.hpp"

#include <cstdlib>
#include <cstring>

#include "x2ap-codec.h"

extern "C" {
#include "E2AP-IEs_GlobalENB-ID.h"
#include "E2AP-IEs_GlobalenGNB-ID.h"
#include "E2nodeComponentInterfaceX2.h"
#include "GlobalE2node-eNB-ID.h"
#include "GlobalE2node-en-gNB-ID.h"
}

namespace agent {

namespace {

constexpr uint32_t kMaxMacroEnbId = (1u << 20) - 1;
constexpr uint32_t kMaxNrPci = 1007, kMaxEutraPci = 503;

// BIT STRING of nbits holding value in its leftmost bits (unused trailing bits 0), buffer calloc'd.
bool set_bits(BIT_STRING_t &s, uint64_t value, int nbits) {
  size_t n = (size_t)(nbits + 7) / 8;
  int unused = (int)(n * 8) - nbits;
  if (nbits < 64 && (value >> nbits) != 0) return false;
  s.buf = (uint8_t *)calloc(1, n);
  if (!s.buf) return false;
  s.size = n;
  s.bits_unused = unused;
  uint64_t v = value << unused;
  for (size_t i = 0; i < n; i++) s.buf[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
  return true;
}

bool set_plmn(PLMN_Identity_t &p, const std::array<uint8_t, 3> &bcd) {
  return OCTET_STRING_fromBuf(&p, (const char *)bcd.data(), 3) == 0;
}

bool fill_en_gnb_id(E2AP_IEs_GlobalenGNB_ID_t &g, const std::array<uint8_t, 3> &plmn, uint32_t gnbId) {
  g.gNB_ID.present = ENGNB_ID_PR_gNB_ID;
  return set_plmn(g.pLMN_Identity, plmn) && set_bits(g.gNB_ID.choice.gNB_ID, gnbId, 32);
}

bool fill_enb_id(E2AP_IEs_GlobalENB_ID_t &g, const std::array<uint8_t, 3> &plmn, uint32_t macroEnbId) {
  g.eNB_ID.present = E2AP_IEs_ENB_ID_PR_macro_eNB_ID;
  return macroEnbId <= kMaxMacroEnbId && set_plmn(g.pLMN_Identity, plmn) &&
         set_bits(g.eNB_ID.choice.macro_eNB_ID, macroEnbId, 20);
}

// The served NR cell of the en-gNB whose gNB ID and cellId are given.
x2c_nr_cell nr_cell(uint32_t gnbId, uint32_t cellId, const uint8_t *mtc, size_t mtcLen) {
  x2c_nr_cell c{};
  c.pci = (uint16_t)cellId;
  c.nr_cell_identity = ((uint64_t)gnbId << 4) | kNrCellPart;
  c.configured_tac = kConfiguredTac;
  c.nr_arfcn = kNrArfcn;
  c.band = kNrBand;
  c.nr_scs = kNrScsIndex;
  c.nr_nrb = kNrNrbIndex;
  c.mtc = mtc;
  c.mtc_len = mtcLen;
  return c;
}

// The served E-UTRA cell of the eNB with this macro eNB ID (= its cellId).
x2c_eutra_cell eutra_cell(uint32_t macroEnbId) {
  x2c_eutra_cell c{};
  c.pci = (uint16_t)macroEnbId;
  c.eutran_cell_identity = (macroEnbId << 8) | kEutraCellPart;
  c.tac = kEutraTac;
  c.dl_earfcn = kEutraDlEarfcn;
  c.ul_earfcn = kEutraUlEarfcn;
  c.bandwidth = kEutraBandwidthIndex;
  return c;
}

// Runs one x2c_* encoder and moves its buffer into out (the encoder's result is read only after it returns).
template <typename Encode>
bool encode_into(Encode encode, Bytes &out) {
  uint8_t *buf = nullptr;
  size_t len = 0;
  if (encode(&buf, &len) != 0) return false;
  out.assign(buf, buf + len);
  x2c_free(buf);
  return true;
}

}  // namespace

bool build_x2_components(const Config &cfg, std::vector<X2Component> &out, std::string &err) {
  out.clear();
  uint8_t mtc[8];
  size_t mtcLen = 0;
  char e[256] = {0};
  if (x2c_measurement_timing_configuration(kNrArfcn, kSsbScsIndex, kSmtcPeriodSf, kSmtcOffsetSf, kSmtcDurationSf,
                                           mtc, &mtcLen, e, sizeof e) != 0) {
    err = std::string("X2 component: ") + e;
    return false;
  }
  const bool gnb = cfg.kind == "gnb";
  const uint32_t self = (uint32_t)cfg.nodeId;
  if (gnb ? self > kMaxNrPci : self > kMaxEutraPci) {
    err = "X2 component: cellId " + std::to_string(self) + " is outside the PCI range";
    return false;
  }
  const uint8_t *plmn = cfg.plmnBcd.data();
  for (uint32_t peer : cfg.x2Peers) {
    if (gnb ? peer > kMaxEutraPci : peer > kMaxNrPci) {
      err = "X2 component: neighbour cellId " + std::to_string(peer) + " is outside the PCI range";
      return false;
    }
    X2Component c;
    c.peerIsEnGnb = !gnb;
    c.peerId = peer;
    bool ok;
    if (gnb) {
      x2c_nr_cell own = nr_cell(cfg.gnbId, self, mtc, mtcLen);
      x2c_eutra_cell theirs = eutra_cell(peer);
      ok = encode_into(
               [&](uint8_t **b, size_t *n) {
                 return x2c_endc_setup_request_en_gnb(plmn, cfg.gnbId, &own, 1, b, n, e, sizeof e);
               },
               c.requestPart) &&
           encode_into(
               [&](uint8_t **b, size_t *n) { return x2c_endc_setup_response_enb(plmn, peer, &theirs, 1, b, n, e, sizeof e); },
               c.responsePart);
    } else {
      x2c_eutra_cell own = eutra_cell(self);
      x2c_nr_cell theirs = nr_cell(peer, peer, mtc, mtcLen);
      ok = encode_into(
               [&](uint8_t **b, size_t *n) { return x2c_endc_setup_request_enb(plmn, self, &own, 1, b, n, e, sizeof e); },
               c.requestPart) &&
           encode_into(
               [&](uint8_t **b, size_t *n) {
                 return x2c_endc_setup_response_en_gnb(plmn, peer, &theirs, 1, b, n, e, sizeof e);
               },
               c.responsePart);
    }
    if (!ok) {
      err = std::string("X2 component for neighbour ") + std::to_string(peer) + ": " + e;
      return false;
    }
    out.push_back(std::move(c));
  }
  return !out.empty();
}

bool fill_global_e2node_id(const Config &cfg, GlobalE2node_ID_t &g, std::string &err) {
  bool ok;
  if (cfg.kind == "gnb") {
    auto *n = (GlobalE2node_en_gNB_ID_t *)calloc(1, sizeof(GlobalE2node_en_gNB_ID_t));
    g.present = GlobalE2node_ID_PR_en_gNB;
    g.choice.en_gNB = n;
    ok = n && fill_en_gnb_id(n->global_en_gNB_ID, cfg.plmnBcd, cfg.gnbId);
  } else {
    auto *n = (GlobalE2node_eNB_ID_t *)calloc(1, sizeof(GlobalE2node_eNB_ID_t));
    g.present = GlobalE2node_ID_PR_eNB;
    g.choice.eNB = n;
    ok = n && fill_enb_id(n->global_eNB_ID, cfg.plmnBcd, (uint32_t)cfg.nodeId);
  }
  if (!ok) err = "Global E2 Node ID: could not be built for node " + std::to_string(cfg.nodeId);
  return ok;
}

bool fill_x2_component_id(const Config &cfg, const X2Component &c, E2nodeComponentID_t &id, std::string &err) {
  auto *x2 = (E2nodeComponentInterfaceX2_t *)calloc(1, sizeof(E2nodeComponentInterfaceX2_t));
  id.present = E2nodeComponentID_PR_e2nodeComponentInterfaceTypeX2;
  id.choice.e2nodeComponentInterfaceTypeX2 = x2;
  bool ok = x2 != nullptr;
  if (ok && c.peerIsEnGnb) {
    // NIST's asn1c names the member type by its unprefixed tag; the descriptor is E2AP-IEs GlobalenGNB-ID.
    auto *g = (E2AP_IEs_GlobalenGNB_ID_t *)calloc(1, sizeof(E2AP_IEs_GlobalenGNB_ID_t));
    x2->global_en_gNB_ID = (struct GlobalenGNB_ID *)g;
    ok = g && fill_en_gnb_id(*g, cfg.plmnBcd, c.peerId);
  } else if (ok) {
    auto *g = (E2AP_IEs_GlobalENB_ID_t *)calloc(1, sizeof(E2AP_IEs_GlobalENB_ID_t));
    x2->global_eNB_ID = (struct GlobalENB_ID *)g;
    ok = g && fill_enb_id(*g, cfg.plmnBcd, c.peerId);
  }
  if (!ok) err = "X2 component ID: could not be built for neighbour " + std::to_string(c.peerId);
  return ok;
}

}  // namespace agent
