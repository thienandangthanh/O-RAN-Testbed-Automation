/* Node IDs and served cell lists of the X2AP codec (see x2ap-codec-internal.h). Every buffer is calloc'd, so
 * ASN_STRUCT_FREE of the enclosing PDU releases it. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x2ap-codec-internal.h"
#include "FDD-Info.h"
#include "FreqBandNrItem.h"
#include "ServedCell-Information.h"
#include "ServedNRCell-Information.h"
#include "TDD-InfoServedNRCell-Information.h"

int x2c_fail(char *err, size_t err_len, const char *fmt, ...) {
  if (err && err_len) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
  }
  return -1;
}

static int set_octets(OCTET_STRING_t *o, const uint8_t *b, size_t n) {
  return OCTET_STRING_fromBuf(o, (const char *)b, (int)n);
}

int x2c_set_bits(BIT_STRING_t *s, uint64_t value, int nbits) {
  size_t n = (size_t)(nbits + 7) / 8;
  int unused = (int)(n * 8) - nbits;
  if (nbits < 64 && (value >> nbits) != 0) return -1;
  s->buf = (uint8_t *)calloc(1, n);
  if (!s->buf) return -1;
  s->size = n;
  s->bits_unused = unused;
  uint64_t v = value << unused;
  for (size_t i = 0; i < n; i++) s->buf[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
  return 0;
}

int x2c_get_bits(const BIT_STRING_t *s, uint64_t *value, int *nbits) {
  if (!s->buf || s->size < 1 || s->size > 8 || s->bits_unused < 0 || s->bits_unused > 7) return -1;
  uint64_t v = 0;
  for (size_t i = 0; i < s->size; i++) v = (v << 8) | s->buf[i];
  *value = v >> s->bits_unused;
  *nbits = (int)s->size * 8 - s->bits_unused;
  return 0;
}

static int add_plmn(BroadcastPLMNs_Item_t *l, const uint8_t plmn[3]) {
  PLMN_Identity_t *p = (PLMN_Identity_t *)calloc(1, sizeof *p);
  if (!p) return -1;
  if (set_octets(p, plmn, 3) != 0 || ASN_SEQUENCE_ADD(&l->list, p) != 0) {
    ASN_STRUCT_FREE(asn_DEF_PLMN_Identity, p);
    return -1;
  }
  return 0;
}

int x2c_fill_global_gnb(GlobalGNB_ID_t *g, const uint8_t plmn[3], uint32_t gnb_id) {
  g->gNB_ID.present = GNB_ID_PR_gNB_ID;
  return set_octets(&g->pLMN_Identity, plmn, 3) != 0 || x2c_set_bits(&g->gNB_ID.choice.gNB_ID, gnb_id, 32) != 0
             ? -1
             : 0;
}

int x2c_fill_global_enb(GlobalENB_ID_t *g, const uint8_t plmn[3], uint32_t macro_enb_id) {
  if (macro_enb_id >> 20) return -1;
  g->eNB_ID.present = ENB_ID_PR_macro_eNB_ID;
  return set_octets(&g->pLMN_Identity, plmn, 3) != 0 ||
                 x2c_set_bits(&g->eNB_ID.choice.macro_eNB_ID, macro_enb_id, 20) != 0
             ? -1
             : 0;
}

/* ServedNRCell-Information (3GPP TS 36.423 §9.2.110): TDD, one NR band, no SUL band, the Configured TAC only. */
static int fill_nr_cell(ServedNRCell_Information_t *c, const uint8_t plmn[3], const x2c_nr_cell *in) {
  c->nrpCI = in->pci;
  if (set_octets(&c->nrCellID.pLMN_Identity, plmn, 3) != 0 ||
      x2c_set_bits(&c->nrCellID.nRcellIdentifier, in->nr_cell_identity, 36) != 0)
    return -1;
  uint8_t tac[2] = {(uint8_t)(in->configured_tac >> 8), (uint8_t)in->configured_tac};
  c->configured_TAC = (TAC_t *)calloc(1, sizeof(TAC_t));
  if (!c->configured_TAC || set_octets(c->configured_TAC, tac, 2) != 0) return -1;
  if (add_plmn(&c->broadcastPLMNs, plmn) != 0) return -1;
  TDD_InfoServedNRCell_Information_t *tdd = (TDD_InfoServedNRCell_Information_t *)calloc(1, sizeof *tdd);
  if (!tdd) return -1;
  c->nrModeInfo.present = ServedNRCell_Information__nrModeInfo_PR_tdd;
  c->nrModeInfo.choice.tdd = tdd;
  tdd->nRFreqInfo.nRARFCN = in->nr_arfcn;
  FreqBandNrItem_t *band = (FreqBandNrItem_t *)calloc(1, sizeof *band);
  if (!band) return -1;
  band->freqBandIndicatorNr = in->band;
  if (ASN_SEQUENCE_ADD(&tdd->nRFreqInfo.freqBandListNr.list, band) != 0) {
    free(band);
    return -1;
  }
  tdd->nR_TxBW.nRSCS = in->nr_scs;
  tdd->nR_TxBW.nRNRB = in->nr_nrb;
  return set_octets(&c->measurementTimingConfiguration, in->mtc, in->mtc_len);
}

int x2c_fill_nr_cells(ServedNRcellsENDCX2ManagementList_t *l, const uint8_t plmn[3], uint32_t gnb_id,
                      const x2c_nr_cell *cells, size_t n_cells) {
  if (!cells || n_cells == 0) return -1;
  for (size_t k = 0; k < n_cells; k++) {
    if (!cells[k].mtc || cells[k].mtc_len == 0 || (cells[k].nr_cell_identity >> 4) != gnb_id) return -1;
    ServedNRcellsENDCX2ManagementList__Member *m =
        (ServedNRcellsENDCX2ManagementList__Member *)calloc(1, sizeof *m);
    if (!m) return -1;
    if (ASN_SEQUENCE_ADD(&l->list, m) != 0) {
      free(m);
      return -1;
    }
    if (fill_nr_cell(&m->servedNRCellInfo, plmn, &cells[k]) != 0) return -1;
  }
  return 0;
}

/* ServedCell-Information (3GPP TS 36.423 §9.2.8): FDD, the same UL and DL transmission bandwidth. */
static int fill_eutra_cell(ServedCell_Information_t *c, const uint8_t plmn[3], const x2c_eutra_cell *in) {
  c->pCI = in->pci;
  uint8_t tac[2] = {(uint8_t)(in->tac >> 8), (uint8_t)in->tac};
  if (set_octets(&c->cellId.pLMN_Identity, plmn, 3) != 0 ||
      x2c_set_bits(&c->cellId.eUTRANcellIdentifier, in->eutran_cell_identity, 28) != 0 ||
      set_octets(&c->tAC, tac, 2) != 0 || add_plmn(&c->broadcastPLMNs, plmn) != 0)
    return -1;
  FDD_Info_t *fdd = (FDD_Info_t *)calloc(1, sizeof *fdd);
  if (!fdd) return -1;
  c->eUTRA_Mode_Info.present = EUTRA_Mode_Info_PR_fDD;
  c->eUTRA_Mode_Info.choice.fDD = fdd;
  fdd->uL_EARFCN = in->ul_earfcn;
  fdd->dL_EARFCN = in->dl_earfcn;
  fdd->uL_Transmission_Bandwidth = in->bandwidth;
  fdd->dL_Transmission_Bandwidth = in->bandwidth;
  return 0;
}

int x2c_fill_eutra_cells(ServedEUTRAcellsENDCX2ManagementList_t *l, const uint8_t plmn[3],
                         const x2c_eutra_cell *cells, size_t n_cells) {
  if (!cells || n_cells == 0) return -1;
  for (size_t k = 0; k < n_cells; k++) {
    ServedEUTRAcellsENDCX2ManagementList__Member *m =
        (ServedEUTRAcellsENDCX2ManagementList__Member *)calloc(1, sizeof *m);
    if (!m) return -1;
    if (ASN_SEQUENCE_ADD(&l->list, m) != 0) {
      free(m);
      return -1;
    }
    if (fill_eutra_cell(&m->servedEUTRACellInfo, plmn, &cells[k]) != 0) return -1;
  }
  return 0;
}

int x2c_read_global_gnb(const GlobalGNB_ID_t *g, x2c_setup_summary *s) {
  uint64_t v;
  int nb;
  if (g->pLMN_Identity.size != 3 || g->gNB_ID.present != GNB_ID_PR_gNB_ID ||
      x2c_get_bits(&g->gNB_ID.choice.gNB_ID, &v, &nb) != 0)
    return -1;
  memcpy(s->plmn, g->pLMN_Identity.buf, 3);
  s->en_gnb = 1, s->node_id = (uint32_t)v, s->node_id_bits = nb;
  return 0;
}

int x2c_read_global_enb(const GlobalENB_ID_t *g, x2c_setup_summary *s) {
  uint64_t v;
  int nb;
  if (g->pLMN_Identity.size != 3 || g->eNB_ID.present != ENB_ID_PR_macro_eNB_ID ||
      x2c_get_bits(&g->eNB_ID.choice.macro_eNB_ID, &v, &nb) != 0)
    return -1;
  memcpy(s->plmn, g->pLMN_Identity.buf, 3);
  s->en_gnb = 0, s->node_id = (uint32_t)v, s->node_id_bits = nb;
  return 0;
}

int x2c_read_nr_cells(const ServedNRcellsENDCX2ManagementList_t *l, x2c_setup_summary *s) {
  uint64_t v;
  int nb;
  s->n_cells = (size_t)l->list.count;
  if (l->list.count < 1 || x2c_get_bits(&l->list.array[0]->servedNRCellInfo.nrCellID.nRcellIdentifier, &v, &nb) != 0 ||
      nb != 36)
    return -1;
  s->first_cell_identity = v, s->first_pci = (uint16_t)l->list.array[0]->servedNRCellInfo.nrpCI;
  return 0;
}

int x2c_read_eutra_cells(const ServedEUTRAcellsENDCX2ManagementList_t *l, x2c_setup_summary *s) {
  uint64_t v;
  int nb;
  s->n_cells = (size_t)l->list.count;
  if (l->list.count < 1 ||
      x2c_get_bits(&l->list.array[0]->servedEUTRACellInfo.cellId.eUTRANcellIdentifier, &v, &nb) != 0 || nb != 28)
    return -1;
  s->first_cell_identity = v, s->first_pci = (uint16_t)l->list.array[0]->servedEUTRACellInfo.pCI;
  return 0;
}

int x2c_encode_pdu(X2AP_PDU_t *pdu, uint8_t **out, size_t *out_len, char *err, size_t err_len) {
  void *buf = NULL;
  ssize_t n = aper_encode_to_new_buffer(&asn_DEF_X2AP_PDU, NULL, pdu, &buf);
  ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, pdu);
  if (n <= 0 || !buf) {
    free(buf);
    return x2c_fail(err, err_len, "APER encoding of the X2AP-PDU failed");
  }
  *out = (uint8_t *)buf;
  *out_len = (size_t)n;
  return 0;
}
