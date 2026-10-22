/* rc-codec: see rc-codec.h. Never calls asn_check_constraints: it loops on
 * RANParameter-bearing RC PDUs in this asn1c (RANParameter-ValueType recursion). */
#include "rc-codec.h"

#include <stdio.h>
#include <string.h>

#include "E2SM-RC-ControlHeader.h"
#include "E2SM-RC-ControlHeader-Format1.h"
#include "E2SM-RC-ControlMessage.h"
#include "E2SM-RC-ControlMessage-Format1.h"
#include "E2SM-RC-ControlMessage-Format1-Item.h"
#include "E2SM-RC-ControlOutcome.h"
#include "E2SM-RC-ControlOutcome-Format1.h"
#include "RANParameter-STRUCTURE.h"
#include "RANParameter-STRUCTURE-Item.h"
#include "RANParameter-Value.h"
#include "RANParameter-ValueType.h"
#include "RANParameter-ValueType-Choice-ElementFalse.h"
#include "RANParameter-ValueType-Choice-Structure.h"
#include "UEID.h"
#include "UEID-GNB.h"

#define RCC_API __attribute__((visibility("default")))

static int fail(char *err, size_t n, const char *what) {
  if (err && n) snprintf(err, n, "%s", what);
  return -1;
}

static int decode_clean(asn_TYPE_descriptor_t *td, void **p, const uint8_t *buf, size_t len) {
  asn_dec_rval_t r = aper_decode_complete(NULL, td, p, buf, len);
  return r.code == RC_OK && r.consumed == len;
}

/* The value type of the member with RAN parameter ID id inside a STRUCTURE value type. */
static const RANParameter_ValueType_t *child(const RANParameter_ValueType_t *vt, long id) {
  if (!vt || vt->present != RANParameter_ValueType_PR_ranP_Choice_Structure || !vt->choice.ranP_Choice_Structure)
    return NULL;
  const RANParameter_STRUCTURE_t *s = vt->choice.ranP_Choice_Structure->ranParameter_Structure;
  if (!s || !s->sequence_of_ranParameters) return NULL;
  for (int i = 0; i < s->sequence_of_ranParameters->list.count; i++) {
    const RANParameter_STRUCTURE_Item_t *it = s->sequence_of_ranParameters->list.array[i];
    if (it && it->ranParameter_ID == id) return it->ranParameter_valueType;
  }
  return NULL;
}

RCC_API int rcc_decode_control(const uint8_t *hdr, size_t hdrLen, const uint8_t *msg, size_t msgLen,
                               rcc_control *out, char *err, size_t errLen) {
  memset(out, 0, sizeof *out);
  int rc = -1;
  E2SM_RC_ControlHeader_t *h = NULL;
  E2SM_RC_ControlMessage_t *m = NULL;
  if (!decode_clean(&asn_DEF_E2SM_RC_ControlHeader, (void **)&h, hdr, hdrLen)) {
    fail(err, errLen, "control header: APER decode failed or trailing octets");
    goto done;
  }
  if (h->ric_controlHeader_formats.present != E2SM_RC_ControlHeader__ric_controlHeader_formats_PR_controlHeader_Format1 ||
      !h->ric_controlHeader_formats.choice.controlHeader_Format1) {
    fail(err, errLen, "control header: not Format 1");
    goto done;
  }
  const E2SM_RC_ControlHeader_Format1_t *f1 = h->ric_controlHeader_formats.choice.controlHeader_Format1;
  out->style = f1->ric_Style_Type;
  out->action = f1->ric_ControlAction_ID;
  if (f1->ueID.present != UEID_PR_gNB_UEID || !f1->ueID.choice.gNB_UEID) {
    fail(err, errLen, "control header: UE ID is not gNB-UEID");
    goto done;
  }
  uintmax_t amf = 0;
  if (asn_INTEGER2umax(&f1->ueID.choice.gNB_UEID->amf_UE_NGAP_ID, &amf) != 0) {
    fail(err, errLen, "control header: bad amf-UE-NGAP-ID");
    goto done;
  }
  out->amfUeNgapId = (uint64_t)amf;

  if (!decode_clean(&asn_DEF_E2SM_RC_ControlMessage, (void **)&m, msg, msgLen)) {
    fail(err, errLen, "control message: APER decode failed or trailing octets");
    goto done;
  }
  if (m->ric_controlMessage_formats.present != E2SM_RC_ControlMessage__ric_controlMessage_formats_PR_controlMessage_Format1 ||
      !m->ric_controlMessage_formats.choice.controlMessage_Format1) {
    fail(err, errLen, "control message: not Format 1");
    goto done;
  }
  const E2SM_RC_ControlMessage_Format1_t *mf = m->ric_controlMessage_formats.choice.controlMessage_Format1;
  const RANParameter_ValueType_t *top = NULL;
  for (int i = 0; i < mf->ranP_List.list.count; i++) {
    const E2SM_RC_ControlMessage_Format1_Item_t *it = mf->ranP_List.list.array[i];
    if (it && it->ranParameter_ID == 1) top = &it->ranParameter_valueType;
  }
  const RANParameter_ValueType_t *cgi = child(child(child(top, 2), 3), 4);
  if (!cgi || cgi->present != RANParameter_ValueType_PR_ranP_Choice_ElementFalse ||
      !cgi->choice.ranP_Choice_ElementFalse || !cgi->choice.ranP_Choice_ElementFalse->ranParameter_value ||
      cgi->choice.ranP_Choice_ElementFalse->ranParameter_value->present != RANParameter_Value_PR_valueOctS) {
    fail(err, errLen, "control message: no NR CGI octet string under RAN parameters 1/2/3/4");
    goto done;
  }
  const OCTET_STRING_t *os = &cgi->choice.ranP_Choice_ElementFalse->ranParameter_value->choice.valueOctS;
  if (os->size <= 0 || (size_t)os->size > sizeof out->targetOctets) {
    fail(err, errLen, "control message: NR CGI octet string of unexpected size");
    goto done;
  }
  memcpy(out->targetOctets, os->buf, (size_t)os->size);
  out->targetLen = (size_t)os->size;
  rc = 0;
done:
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader, h);
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, m);
  return rc;
}

RCC_API long rcc_encode_outcome_format1_empty(uint8_t *buf, size_t cap) {
  E2SM_RC_ControlOutcome_t o;
  E2SM_RC_ControlOutcome_Format1_t f;
  memset(&o, 0, sizeof o);
  memset(&f, 0, sizeof f);
  o.ric_controlOutcome_formats.present = E2SM_RC_ControlOutcome__ric_controlOutcome_formats_PR_controlOutcome_Format1;
  o.ric_controlOutcome_formats.choice.controlOutcome_Format1 = &f;
  asn_enc_rval_t r = aper_encode_to_buffer(&asn_DEF_E2SM_RC_ControlOutcome, NULL, &o, buf, cap);
  if (r.encoded < 0) return -1;
  long n = (long)((r.encoded + 7) / 8);
  return (size_t)n <= cap ? n : -1;
}

static long encode_to(asn_TYPE_descriptor_t *td, const void *v, uint8_t *out, size_t cap) {
  asn_enc_rval_t r = aper_encode_to_buffer(td, NULL, v, out, cap);
  if (r.encoded < 0) return -1;
  long n = (long)((r.encoded + 7) / 8);
  return (size_t)n <= cap ? n : -1;
}

RCC_API long rcc_test_reencode_header(const uint8_t *hdr, size_t hdrLen, long style, long action, uint8_t *out,
                                      size_t cap) {
  E2SM_RC_ControlHeader_t *h = NULL;
  long n = -1;
  if (decode_clean(&asn_DEF_E2SM_RC_ControlHeader, (void **)&h, hdr, hdrLen) &&
      h->ric_controlHeader_formats.present == E2SM_RC_ControlHeader__ric_controlHeader_formats_PR_controlHeader_Format1) {
    h->ric_controlHeader_formats.choice.controlHeader_Format1->ric_Style_Type = style;
    h->ric_controlHeader_formats.choice.controlHeader_Format1->ric_ControlAction_ID = action;
    n = encode_to(&asn_DEF_E2SM_RC_ControlHeader, h, out, cap);
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader, h);
  return n;
}

RCC_API long rcc_test_reencode_target(const uint8_t *msg, size_t msgLen, const uint8_t *target, size_t targetLen,
                                      uint8_t *out, size_t cap) {
  E2SM_RC_ControlMessage_t *m = NULL;
  long n = -1;
  if (decode_clean(&asn_DEF_E2SM_RC_ControlMessage, (void **)&m, msg, msgLen) &&
      m->ric_controlMessage_formats.present == E2SM_RC_ControlMessage__ric_controlMessage_formats_PR_controlMessage_Format1) {
    const E2SM_RC_ControlMessage_Format1_t *mf = m->ric_controlMessage_formats.choice.controlMessage_Format1;
    const RANParameter_ValueType_t *top = NULL;
    for (int i = 0; i < mf->ranP_List.list.count; i++)
      if (mf->ranP_List.list.array[i]->ranParameter_ID == 1) top = &mf->ranP_List.list.array[i]->ranParameter_valueType;
    const RANParameter_ValueType_t *cgi = child(child(child(top, 2), 3), 4);
    if (cgi && cgi->present == RANParameter_ValueType_PR_ranP_Choice_ElementFalse &&
        cgi->choice.ranP_Choice_ElementFalse->ranParameter_value) {
      OCTET_STRING_t *os = &cgi->choice.ranP_Choice_ElementFalse->ranParameter_value->choice.valueOctS;
      if (OCTET_STRING_fromBuf(os, (const char *)target, (int)targetLen) == 0)
        n = encode_to(&asn_DEF_E2SM_RC_ControlMessage, m, out, cap);
    }
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, m);
  return n;
}
