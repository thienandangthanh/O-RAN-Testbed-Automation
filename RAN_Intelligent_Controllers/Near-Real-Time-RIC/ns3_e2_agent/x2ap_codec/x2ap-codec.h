/* X2AP codec of the agent: the EN-DC X2 SETUP REQUEST and RESPONSE (3GPP TS 36.423 v19.1.0 §9.1.2.31, §9.1.2.32)
 * that an E2 node puts in the request and response parts of its X2 E2 node component (O-RAN E2AP v03.00 §9.2.27),
 * and the 3GPP TS 38.331 MeasurementTimingConfiguration that a served NR cell carries.
 *
 * libx2ap_codec.so is built from asn1c output of the X2AP ASN.1 (x2ap-v19.1.0.asn, see SOURCES.txt) with hidden
 * symbols; only the x2c_* functions below are exported, so its asn1c runtime cannot clash with the E2AP/KPM asn1c
 * the agent links. Encoded buffers are the APER bytes of a whole X2AP-PDU (initiatingMessage for a request,
 * successfulOutcome for a response; procedure code id-endcX2Setup, criticality reject), returned in malloc'd memory released with x2c_free. Every function returns 0 on success and
 * -1 on failure, with a message in err (when err is not NULL). */
#ifndef NS3_E2_AGENT_X2AP_CODEC_H
#define NS3_E2_AGENT_X2AP_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X2C_EXPORT __attribute__((visibility("default")))

/* One TDD NR cell (ServedNRCell-Information, §9.2.110) of an en-gNB. */
typedef struct {
  uint16_t pci;                 /* NR-PCI 0..1007 */
  uint64_t nr_cell_identity;    /* 36-bit NR Cell Identity (gNB ID in the leftmost bits) */
  uint16_t configured_tac;      /* Configured TAC, 2 octets; no 5GS-TAC is sent (an EN-DC cell without 5GS service) */
  long nr_arfcn;                /* NRARFCN: the NR-ARFCN of Point A, CRB 0 of the carrier (36.423 §9.2.106) */
  long band;                    /* NR operating band (freqBandIndicatorNr) */
  long nr_scs;                  /* NRSCS enumeration index: 0 scs15, 1 scs30, 2 scs60, 3 scs120 */
  long nr_nrb;                  /* NRNRB enumeration index (e.g. 7 = nrb51) */
  const uint8_t *mtc;           /* MeasurementTimingConfiguration octets (x2c_measurement_timing_configuration) */
  size_t mtc_len;
} x2c_nr_cell;

/* One FDD E-UTRA cell (Served Cell Information, §9.2.8) of an eNB. */
typedef struct {
  uint16_t pci;                 /* PCI 0..503 */
  uint32_t eutran_cell_identity; /* 28-bit E-UTRAN Cell Identity */
  uint16_t tac;                 /* TAC, 2 octets */
  long dl_earfcn, ul_earfcn;
  long bandwidth;               /* Transmission-Bandwidth enumeration index (e.g. 5 = bw100) */
} x2c_eutra_cell;

/* ENDCX2SetupRequest from an en-gNB: init-en-gNB with the Global en-gNB ID (PLMN, 32-bit gNB ID) and its served
 * NR cells. plmn is the 3-octet BCD PLMN identity. */
X2C_EXPORT int x2c_endc_setup_request_en_gnb(const uint8_t plmn[3], uint32_t gnb_id, const x2c_nr_cell *cells,
                                             size_t n_cells, uint8_t **out, size_t *out_len, char *err,
                                             size_t err_len);

/* ENDCX2SetupRequest from an eNB: init-eNB with the Global eNB ID (PLMN, 20-bit macro eNB ID) and its served
 * E-UTRA cells. */
X2C_EXPORT int x2c_endc_setup_request_enb(const uint8_t plmn[3], uint32_t macro_enb_id, const x2c_eutra_cell *cells,
                                          size_t n_cells, uint8_t **out, size_t *out_len, char *err, size_t err_len);

/* ENDCX2SetupResponse from an en-gNB (respond-en-gNB) and from an eNB (respond-eNB): the responding node's global ID
 * and served cells, the same IEs and checks as the request. */
X2C_EXPORT int x2c_endc_setup_response_en_gnb(const uint8_t plmn[3], uint32_t gnb_id, const x2c_nr_cell *cells,
                                              size_t n_cells, uint8_t **out, size_t *out_len, char *err,
                                              size_t err_len);
X2C_EXPORT int x2c_endc_setup_response_enb(const uint8_t plmn[3], uint32_t macro_enb_id, const x2c_eutra_cell *cells,
                                           size_t n_cells, uint8_t **out, size_t *out_len, char *err, size_t err_len);

/* What a decoded EN-DC X2 Setup message says about its node (the initiating node of a request, the responding node
 * of a response) and the node's first served cell. */
typedef struct {
  int response;                 /* 1: ENDCX2SetupResponse, 0: ENDCX2SetupRequest */
  int en_gnb;                   /* 1: the node is an en-gNB, 0: an eNB */
  uint8_t plmn[3];
  uint32_t node_id;             /* gNB ID (en-gNB) or macro eNB ID (eNB) */
  int node_id_bits;             /* 22..32 for a gNB ID, 20 for a macro eNB ID */
  size_t n_cells;
  uint64_t first_cell_identity; /* NR Cell Identity (36 bits) or E-UTRAN Cell Identity (28 bits) */
  uint16_t first_pci;
} x2c_setup_summary;

/* Decode a whole X2AP-PDU that must be an ENDCX2SetupRequest or ENDCX2SetupResponse with a usable node ID and
 * served cell; fails on anything else, including trailing octets. */
X2C_EXPORT int x2c_decode_endc_setup(const uint8_t *buf, size_t len, x2c_setup_summary *s, char *err,
                                     size_t err_len);

/* UPER MeasurementTimingConfiguration (3GPP TS 38.331 v19.4.0, NR-InterNodeDefinitions) with one MeasTiming:
 * SSB at NR-ARFCN arfcn (0..3279165), SSB subcarrier spacing scs (SubcarrierSpacing index, 0..7), SMTC
 * periodicity period_sf (5, 10, 20, 40, 80 or 160 subframes) with offset 0..period_sf-1, and duration_sf (1..5).
 * Writes at most 8 octets to out. */
X2C_EXPORT int x2c_measurement_timing_configuration(long arfcn, int scs, int period_sf, int offset, int duration_sf,
                                                    uint8_t out[8], size_t *out_len, char *err, size_t err_len);

X2C_EXPORT void x2c_free(void *p);

#ifdef __cplusplus
}
#endif

#endif
