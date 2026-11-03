/* Helpers shared by the X2AP codec's source files (not exported; see x2ap-codec.h for the API). */
#ifndef NS3_E2_AGENT_X2AP_CODEC_INTERNAL_H
#define NS3_E2_AGENT_X2AP_CODEC_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "x2ap-codec.h"
#include "BIT_STRING.h"
#include "GlobalENB-ID.h"
#include "GlobalGNB-ID.h"
#include "OCTET_STRING.h"
#include "ServedEUTRAcellsENDCX2ManagementList.h"
#include "ServedNRcellsENDCX2ManagementList.h"
#include "X2AP-PDU.h"

/* Writes the message to err (when given) and returns -1. */
int x2c_fail(char *err, size_t err_len, const char *fmt, ...);

/* BIT STRING of nbits holding value in its leftmost bits; the unused trailing bits are 0. */
int x2c_set_bits(BIT_STRING_t *s, uint64_t value, int nbits);
/* Value and bit length of a BIT STRING of at most 64 bits. */
int x2c_get_bits(const BIT_STRING_t *s, uint64_t *value, int *nbits);

/* Global en-gNB ID (PLMN, 32-bit gNB ID) and Global eNB ID (PLMN, 20-bit macro eNB ID). */
int x2c_fill_global_gnb(GlobalGNB_ID_t *g, const uint8_t plmn[3], uint32_t gnb_id);
int x2c_fill_global_enb(GlobalENB_ID_t *g, const uint8_t plmn[3], uint32_t macro_enb_id);

/* Served cell lists of an en-gNB (TDD NR cells) and of an eNB (FDD E-UTRA cells). The NR list requires every cell's
 * NR Cell Identity to start with gnb_id (its leftmost 32 bits) and every cell to carry an MTC. */
int x2c_fill_nr_cells(ServedNRcellsENDCX2ManagementList_t *l, const uint8_t plmn[3], uint32_t gnb_id,
                      const x2c_nr_cell *cells, size_t n_cells);
int x2c_fill_eutra_cells(ServedEUTRAcellsENDCX2ManagementList_t *l, const uint8_t plmn[3],
                         const x2c_eutra_cell *cells, size_t n_cells);

/* Summary readers: node ID from a Global en-gNB / eNB ID, first cell from a served cell list. */
int x2c_read_global_gnb(const GlobalGNB_ID_t *g, x2c_setup_summary *s);
int x2c_read_global_enb(const GlobalENB_ID_t *g, x2c_setup_summary *s);
int x2c_read_nr_cells(const ServedNRcellsENDCX2ManagementList_t *l, x2c_setup_summary *s);
int x2c_read_eutra_cells(const ServedEUTRAcellsENDCX2ManagementList_t *l, x2c_setup_summary *s);

/* APER-encodes the PDU into a new buffer and frees the PDU in every case. */
int x2c_encode_pdu(X2AP_PDU_t *pdu, uint8_t **out, size_t *out_len, char *err, size_t err_len);

#endif
