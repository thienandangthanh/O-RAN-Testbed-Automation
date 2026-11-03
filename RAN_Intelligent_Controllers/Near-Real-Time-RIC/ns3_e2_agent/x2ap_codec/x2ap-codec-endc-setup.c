/* EN-DC X2 Setup messages of the X2AP codec (see x2ap-codec.h): ENDCX2SetupRequest (3GPP TS 36.423 §9.1.2.31) and
 * ENDCX2SetupResponse (§9.1.2.32), each a whole X2AP-PDU with procedure code id-endcX2Setup, criticality reject.
 * The node-type containers hold the same two IEs in both messages: the node's global ID and its served cells. */
#include <stdlib.h>
#include <string.h>

#include "x2ap-codec-internal.h"
#include "ENDCX2SetupRequest.h"
#include "ENDCX2SetupResponse.h"
#include "InitiatingMessage.h"
#include "InitiatingNodeType-EndcX2Setup.h"
#include "ProcedureCode.h"
#include "ProtocolIE-Container.h"
#include "ProtocolIE-Field.h"
#include "ProtocolIE-ID.h"
#include "RespondingNodeType-EndcX2Setup.h"
#include "SuccessfulOutcome.h"

/* Appends a zeroed IE of type T to container c; evaluates to the IE or NULL. */
#define ADD_IE(T, c) ((T *)add_ie(&(c)->list, sizeof(T)))
static void *add_ie(void *list, size_t size) {
  void *ie = calloc(1, size);
  if (ie && ASN_SEQUENCE_ADD(list, ie) != 0) {
    free(ie);
    return NULL;
  }
  return ie;
}

/* The en-gNB IEs (id-Globalen-gNB-ID, id-ServedNRcellsENDCX2ManagementList, both reject) of either message. */
#define FILL_EN_GNB_IES(IE_T, PR, c, plmn, gnb_id, cells, n_cells)                                   \
  do {                                                                                               \
    IE_T *id_ie = ADD_IE(IE_T, c), *cells_ie = id_ie ? ADD_IE(IE_T, c) : NULL;                       \
    if (!cells_ie) break;                                                                            \
    id_ie->id = ProtocolIE_ID_id_Globalen_gNB_ID, id_ie->criticality = Criticality_reject;           \
    id_ie->value.present = PR##_GlobalGNB_ID;                                                        \
    cells_ie->id = ProtocolIE_ID_id_ServedNRcellsENDCX2ManagementList;                               \
    cells_ie->criticality = Criticality_reject;                                                      \
    cells_ie->value.present = PR##_ServedNRcellsENDCX2ManagementList;                                \
    ok = x2c_fill_global_gnb(&id_ie->value.choice.GlobalGNB_ID, plmn, gnb_id) == 0 &&                \
         x2c_fill_nr_cells(&cells_ie->value.choice.ServedNRcellsENDCX2ManagementList, plmn, gnb_id, \
                           cells, n_cells) == 0;                                                     \
  } while (0)

/* The eNB IEs (id-GlobalENB-ID, id-ServedEUTRAcellsENDCX2ManagementList, both reject) of either message. */
#define FILL_ENB_IES(IE_T, PR, c, plmn, enb_id, cells, n_cells)                                     \
  do {                                                                                              \
    IE_T *id_ie = ADD_IE(IE_T, c), *cells_ie = id_ie ? ADD_IE(IE_T, c) : NULL;                      \
    if (!cells_ie) break;                                                                           \
    id_ie->id = ProtocolIE_ID_id_GlobalENB_ID, id_ie->criticality = Criticality_reject;             \
    id_ie->value.present = PR##_GlobalENB_ID;                                                       \
    cells_ie->id = ProtocolIE_ID_id_ServedEUTRAcellsENDCX2ManagementList;                           \
    cells_ie->criticality = Criticality_reject;                                                     \
    cells_ie->value.present = PR##_ServedEUTRAcellsENDCX2ManagementList;                            \
    ok = x2c_fill_global_enb(&id_ie->value.choice.GlobalENB_ID, plmn, enb_id) == 0 &&               \
         x2c_fill_eutra_cells(&cells_ie->value.choice.ServedEUTRAcellsENDCX2ManagementList, plmn,   \
                              cells, n_cells) == 0;                                                 \
  } while (0)

/* X2AP-PDU initiatingMessage with an ENDCX2SetupRequest holding one id-InitiatingNodeType-EndcX2Setup IE. */
static X2AP_PDU_t *new_request(InitiatingNodeType_EndcX2Setup_t **node) {
  X2AP_PDU_t *pdu = (X2AP_PDU_t *)calloc(1, sizeof *pdu);
  if (!pdu) return NULL;
  InitiatingMessage_t *im = (InitiatingMessage_t *)calloc(1, sizeof *im);
  pdu->present = X2AP_PDU_PR_initiatingMessage;
  pdu->choice.initiatingMessage = im;
  ENDCX2SetupRequest_IEs_t *ie = im ? ADD_IE(ENDCX2SetupRequest_IEs_t, &im->value.choice.ENDCX2SetupRequest.protocolIEs) : NULL;
  if (!ie) {
    ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, pdu);
    return NULL;
  }
  im->procedureCode = ProcedureCode_id_endcX2Setup;
  im->criticality = Criticality_reject;
  im->value.present = InitiatingMessage__value_PR_ENDCX2SetupRequest;
  ie->id = ProtocolIE_ID_id_InitiatingNodeType_EndcX2Setup;
  ie->criticality = Criticality_reject;
  ie->value.present = ENDCX2SetupRequest_IEs__value_PR_InitiatingNodeType_EndcX2Setup;
  *node = &ie->value.choice.InitiatingNodeType_EndcX2Setup;
  return pdu;
}

/* X2AP-PDU successfulOutcome with an ENDCX2SetupResponse holding one id-RespondingNodeType-EndcX2Setup IE. */
static X2AP_PDU_t *new_response(RespondingNodeType_EndcX2Setup_t **node) {
  X2AP_PDU_t *pdu = (X2AP_PDU_t *)calloc(1, sizeof *pdu);
  if (!pdu) return NULL;
  SuccessfulOutcome_t *so = (SuccessfulOutcome_t *)calloc(1, sizeof *so);
  pdu->present = X2AP_PDU_PR_successfulOutcome;
  pdu->choice.successfulOutcome = so;
  ENDCX2SetupResponse_IEs_t *ie = so ? ADD_IE(ENDCX2SetupResponse_IEs_t, &so->value.choice.ENDCX2SetupResponse.protocolIEs) : NULL;
  if (!ie) {
    ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, pdu);
    return NULL;
  }
  so->procedureCode = ProcedureCode_id_endcX2Setup;
  so->criticality = Criticality_reject;
  so->value.present = SuccessfulOutcome__value_PR_ENDCX2SetupResponse;
  ie->id = ProtocolIE_ID_id_RespondingNodeType_EndcX2Setup;
  ie->criticality = Criticality_reject;
  ie->value.present = ENDCX2SetupResponse_IEs__value_PR_RespondingNodeType_EndcX2Setup;
  *node = &ie->value.choice.RespondingNodeType_EndcX2Setup;
  return pdu;
}

static int finish(X2AP_PDU_t *pdu, int ok, const char *what, uint8_t **out, size_t *out_len, char *err,
                  size_t err_len) {
  if (!ok) {
    ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, pdu);
    return x2c_fail(err, err_len, "%s: could not build the PDU (bad node ID or cell)", what);
  }
  return x2c_encode_pdu(pdu, out, out_len, err, err_len);
}

int x2c_endc_setup_request_en_gnb(const uint8_t plmn[3], uint32_t gnb_id, const x2c_nr_cell *cells, size_t n_cells,
                                  uint8_t **out, size_t *out_len, char *err, size_t err_len) {
  if (!plmn || !out || !out_len) return x2c_fail(err, err_len, "en-gNB setup request: bad arguments");
  InitiatingNodeType_EndcX2Setup_t *node = NULL;
  X2AP_PDU_t *pdu = new_request(&node);
  if (!pdu) return x2c_fail(err, err_len, "en-gNB setup request: out of memory");
  ProtocolIE_Container_11469P76_t *c = (ProtocolIE_Container_11469P76_t *)calloc(1, sizeof *c);
  int ok = 0;
  if (c) {
    node->present = InitiatingNodeType_EndcX2Setup_PR_init_en_gNB;
    node->choice.init_en_gNB = (struct ProtocolIE_Container *)c;
    FILL_EN_GNB_IES(En_gNB_ENDCX2SetupReqIEs_t, En_gNB_ENDCX2SetupReqIEs__value_PR, c, plmn, gnb_id, cells, n_cells);
  }
  return finish(pdu, ok, "en-gNB setup request", out, out_len, err, err_len);
}

int x2c_endc_setup_request_enb(const uint8_t plmn[3], uint32_t macro_enb_id, const x2c_eutra_cell *cells,
                               size_t n_cells, uint8_t **out, size_t *out_len, char *err, size_t err_len) {
  if (!plmn || !out || !out_len) return x2c_fail(err, err_len, "eNB setup request: bad arguments");
  InitiatingNodeType_EndcX2Setup_t *node = NULL;
  X2AP_PDU_t *pdu = new_request(&node);
  if (!pdu) return x2c_fail(err, err_len, "eNB setup request: out of memory");
  ProtocolIE_Container_11469P75_t *c = (ProtocolIE_Container_11469P75_t *)calloc(1, sizeof *c);
  int ok = 0;
  if (c) {
    node->present = InitiatingNodeType_EndcX2Setup_PR_init_eNB;
    node->choice.init_eNB = (struct ProtocolIE_Container *)c;
    FILL_ENB_IES(ENB_ENDCX2SetupReqIEs_t, ENB_ENDCX2SetupReqIEs__value_PR, c, plmn, macro_enb_id, cells, n_cells);
  }
  return finish(pdu, ok, "eNB setup request", out, out_len, err, err_len);
}

int x2c_endc_setup_response_en_gnb(const uint8_t plmn[3], uint32_t gnb_id, const x2c_nr_cell *cells, size_t n_cells,
                                   uint8_t **out, size_t *out_len, char *err, size_t err_len) {
  if (!plmn || !out || !out_len) return x2c_fail(err, err_len, "en-gNB setup response: bad arguments");
  RespondingNodeType_EndcX2Setup_t *node = NULL;
  X2AP_PDU_t *pdu = new_response(&node);
  if (!pdu) return x2c_fail(err, err_len, "en-gNB setup response: out of memory");
  ProtocolIE_Container_11469P79_t *c = (ProtocolIE_Container_11469P79_t *)calloc(1, sizeof *c);
  int ok = 0;
  if (c) {
    node->present = RespondingNodeType_EndcX2Setup_PR_respond_en_gNB;
    node->choice.respond_en_gNB = (struct ProtocolIE_Container *)c;
    FILL_EN_GNB_IES(En_gNB_ENDCX2SetupReqAckIEs_t, En_gNB_ENDCX2SetupReqAckIEs__value_PR, c, plmn, gnb_id, cells,
                    n_cells);
  }
  return finish(pdu, ok, "en-gNB setup response", out, out_len, err, err_len);
}

int x2c_endc_setup_response_enb(const uint8_t plmn[3], uint32_t macro_enb_id, const x2c_eutra_cell *cells,
                                size_t n_cells, uint8_t **out, size_t *out_len, char *err, size_t err_len) {
  if (!plmn || !out || !out_len) return x2c_fail(err, err_len, "eNB setup response: bad arguments");
  RespondingNodeType_EndcX2Setup_t *node = NULL;
  X2AP_PDU_t *pdu = new_response(&node);
  if (!pdu) return x2c_fail(err, err_len, "eNB setup response: out of memory");
  ProtocolIE_Container_11469P78_t *c = (ProtocolIE_Container_11469P78_t *)calloc(1, sizeof *c);
  int ok = 0;
  if (c) {
    node->present = RespondingNodeType_EndcX2Setup_PR_respond_eNB;
    node->choice.respond_eNB = (struct ProtocolIE_Container *)c;
    FILL_ENB_IES(ENB_ENDCX2SetupReqAckIEs_t, ENB_ENDCX2SetupReqAckIEs__value_PR, c, plmn, macro_enb_id, cells,
                 n_cells);
  }
  return finish(pdu, ok, "eNB setup response", out, out_len, err, err_len);
}

/* Reads the global-ID and served-cell IEs of a node-type container; true when both were usable. */
#define READ_NODE_IES(c, PR, read_id, ID_MEMBER, read_cells, CELLS_MEMBER, s)                          \
  do {                                                                                                \
    int have_id = 0, have_cells = 0;                                                                  \
    for (int i = 0; i < (c)->list.count; i++) {                                                       \
      if ((c)->list.array[i]->value.present == PR##_##ID_MEMBER)                                      \
        have_id = read_id(&(c)->list.array[i]->value.choice.ID_MEMBER, s) == 0;                       \
      else if ((c)->list.array[i]->value.present == PR##_##CELLS_MEMBER)                              \
        have_cells = read_cells(&(c)->list.array[i]->value.choice.CELLS_MEMBER, s) == 0;              \
    }                                                                                                 \
    ok = have_id && have_cells;                                                                       \
  } while (0)

int x2c_decode_endc_setup(const uint8_t *buf, size_t len, x2c_setup_summary *s, char *err, size_t err_len) {
  X2AP_PDU_t *pdu = NULL;
  int ok = 0;
  memset(s, 0, sizeof *s);
  asn_dec_rval_t r = aper_decode_complete(NULL, &asn_DEF_X2AP_PDU, (void **)&pdu, buf, len);
  if (r.code != RC_OK || r.consumed != len) {
    ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, pdu);
    return x2c_fail(err, err_len, "not a whole APER X2AP-PDU");
  }
  if (pdu->present == X2AP_PDU_PR_initiatingMessage &&
      pdu->choice.initiatingMessage->procedureCode == ProcedureCode_id_endcX2Setup &&
      pdu->choice.initiatingMessage->value.present == InitiatingMessage__value_PR_ENDCX2SetupRequest) {
    ENDCX2SetupRequest_t *m = &pdu->choice.initiatingMessage->value.choice.ENDCX2SetupRequest;
    for (int i = 0; i < m->protocolIEs.list.count; i++) {
      if (m->protocolIEs.list.array[i]->value.present != ENDCX2SetupRequest_IEs__value_PR_InitiatingNodeType_EndcX2Setup)
        continue;
      InitiatingNodeType_EndcX2Setup_t *n = &m->protocolIEs.list.array[i]->value.choice.InitiatingNodeType_EndcX2Setup;
      if (n->present == InitiatingNodeType_EndcX2Setup_PR_init_en_gNB) {
        ProtocolIE_Container_11469P76_t *c = (ProtocolIE_Container_11469P76_t *)n->choice.init_en_gNB;
        READ_NODE_IES(c, En_gNB_ENDCX2SetupReqIEs__value_PR, x2c_read_global_gnb, GlobalGNB_ID, x2c_read_nr_cells,
                      ServedNRcellsENDCX2ManagementList, s);
      } else if (n->present == InitiatingNodeType_EndcX2Setup_PR_init_eNB) {
        ProtocolIE_Container_11469P75_t *c = (ProtocolIE_Container_11469P75_t *)n->choice.init_eNB;
        READ_NODE_IES(c, ENB_ENDCX2SetupReqIEs__value_PR, x2c_read_global_enb, GlobalENB_ID, x2c_read_eutra_cells,
                      ServedEUTRAcellsENDCX2ManagementList, s);
      }
    }
  } else if (pdu->present == X2AP_PDU_PR_successfulOutcome &&
             pdu->choice.successfulOutcome->procedureCode == ProcedureCode_id_endcX2Setup &&
             pdu->choice.successfulOutcome->value.present == SuccessfulOutcome__value_PR_ENDCX2SetupResponse) {
    ENDCX2SetupResponse_t *m = &pdu->choice.successfulOutcome->value.choice.ENDCX2SetupResponse;
    s->response = 1;
    for (int i = 0; i < m->protocolIEs.list.count; i++) {
      if (m->protocolIEs.list.array[i]->value.present !=
          ENDCX2SetupResponse_IEs__value_PR_RespondingNodeType_EndcX2Setup)
        continue;
      RespondingNodeType_EndcX2Setup_t *n = &m->protocolIEs.list.array[i]->value.choice.RespondingNodeType_EndcX2Setup;
      if (n->present == RespondingNodeType_EndcX2Setup_PR_respond_en_gNB) {
        ProtocolIE_Container_11469P79_t *c = (ProtocolIE_Container_11469P79_t *)n->choice.respond_en_gNB;
        READ_NODE_IES(c, En_gNB_ENDCX2SetupReqAckIEs__value_PR, x2c_read_global_gnb, GlobalGNB_ID,
                      x2c_read_nr_cells, ServedNRcellsENDCX2ManagementList, s);
      } else if (n->present == RespondingNodeType_EndcX2Setup_PR_respond_eNB) {
        ProtocolIE_Container_11469P78_t *c = (ProtocolIE_Container_11469P78_t *)n->choice.respond_eNB;
        READ_NODE_IES(c, ENB_ENDCX2SetupReqAckIEs__value_PR, x2c_read_global_enb, GlobalENB_ID,
                      x2c_read_eutra_cells, ServedEUTRAcellsENDCX2ManagementList, s);
      }
    }
  } else {
    ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, pdu);
    return x2c_fail(err, err_len, "not an ENDCX2SetupRequest or ENDCX2SetupResponse");
  }
  ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, pdu);
  return ok ? 0 : x2c_fail(err, err_len, "EN-DC X2 Setup message without a usable node ID or served cell");
}
