/* E2SM-RC RAN Function Definition of the agent's RAN function 3 (see rc-codec.h). Names and IDs are those of O-RAN
 * E2SM-RC v03.00 (identical in v01.03): §7.2 (RAN Function name), §7.6.6 (CONTROL Service Style 5 "Dual Connectivity
 * Control", action 3 "DC PSCell Change control", RAN parameters §8.4.6.3), with Control Header, Message and Outcome
 * Format 1 (§7.6.6.2-5); no Call Process ID format (no INSERT service). It is the only control the agent executes,
 * and the definition lists every RAN parameter the control carries: 1 Target PSCell ID, its CHOICE Target Cell (2),
 * NR Cell (3) and NR CGI (4). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rc-codec.h"
#include "ControlAction-RANParameter-Item.h"
#include "E2SM-RC-RANFunctionDefinition.h"
#include "RANFunctionDefinition-Control.h"
#include "RANFunctionDefinition-Control-Action-Item.h"
#include "RANFunctionDefinition-Control-Item.h"

#define RCC_API __attribute__((visibility("default")))

/* The E2SM OID: the object identifier of the E2SM-RC-IEs module (§9.4.2). */
static const char kRcOid[] = "1.3.6.1.4.1.53148.1.1.2.3";

typedef struct {
  long style;
  const char *style_name;
  long action;
  const char *action_name;
  const char *target_name;  /* RAN parameter 1 */
} control_style;

static const control_style kStyles[] = {
    {5, "Dual Connectivity Control", 3, "DC PSCell Change control", "Target PSCell ID"},
};

static int set_str(OCTET_STRING_t *s, const char *v) { return OCTET_STRING_fromBuf(s, v, -1) == 0 ? 0 : -1; }

#define ADD(list, T, p) ((p) = (T *)calloc(1, sizeof(T)), (p) && ASN_SEQUENCE_ADD((list), (p)) == 0 ? 0 : (free(p), -1))

static int add_param(struct RANFunctionDefinition_Control_Action_Item__ran_ControlActionParameters_List *l, long id,
                     const char *name) {
  ControlAction_RANParameter_Item_t *p;
  if (ADD(&l->list, ControlAction_RANParameter_Item_t, p) != 0) return -1;
  p->ranParameter_ID = id;
  return set_str(&p->ranParameter_name, name);
}

static int add_style(RANFunctionDefinition_Control_t *ctl, const control_style *cs) {
  RANFunctionDefinition_Control_Item_t *it;
  if (ADD(&ctl->ric_ControlStyle_List.list, RANFunctionDefinition_Control_Item_t, it) != 0) return -1;
  it->ric_ControlStyle_Type = cs->style;
  it->ric_ControlHeaderFormat_Type = 1;
  it->ric_ControlMessageFormat_Type = 1;
  it->ric_ControlOutcomeFormat_Type = 1;
  if (set_str(&it->ric_ControlStyle_Name, cs->style_name) != 0) return -1;
  it->ric_ControlAction_List = calloc(1, sizeof *it->ric_ControlAction_List);
  if (!it->ric_ControlAction_List) return -1;
  RANFunctionDefinition_Control_Action_Item_t *a;
  if (ADD(&it->ric_ControlAction_List->list, RANFunctionDefinition_Control_Action_Item_t, a) != 0) return -1;
  a->ric_ControlAction_ID = cs->action;
  a->ueGroup_ControlAction_Supported = RANFunctionDefinition_Control_Action_Item__ueGroup_ControlAction_Supported_false;
  if (set_str(&a->ric_ControlAction_Name, cs->action_name) != 0) return -1;
  a->ran_ControlActionParameters_List = calloc(1, sizeof *a->ran_ControlActionParameters_List);
  if (!a->ran_ControlActionParameters_List) return -1;
  return add_param(a->ran_ControlActionParameters_List, 1, cs->target_name) ||
                 add_param(a->ran_ControlActionParameters_List, 2, "CHOICE Target Cell") ||
                 add_param(a->ran_ControlActionParameters_List, 3, "NR Cell") ||
                 add_param(a->ran_ControlActionParameters_List, 4, "NR CGI")
             ? -1
             : 0;
}

RCC_API const char *rcc_ran_function_oid(void) { return kRcOid; }

RCC_API long rcc_encode_ran_function_definition(uint8_t *buf, size_t cap) {
  E2SM_RC_RANFunctionDefinition_t *d = calloc(1, sizeof *d);
  long n = -1;
  if (!d) return -1;
  d->ranFunctionDefinition_Control = calloc(1, sizeof *d->ranFunctionDefinition_Control);
  int bad = !d->ranFunctionDefinition_Control || set_str(&d->ranFunction_Name.ranFunction_ShortName, "ORAN-E2SM-RC") ||
            set_str(&d->ranFunction_Name.ranFunction_E2SM_OID, kRcOid) ||
            set_str(&d->ranFunction_Name.ranFunction_Description, "RAN Control");
  for (size_t i = 0; !bad && i < sizeof kStyles / sizeof kStyles[0]; i++)
    bad = add_style(d->ranFunctionDefinition_Control, &kStyles[i]) != 0;
  if (!bad) {
    asn_enc_rval_t r = aper_encode_to_buffer(&asn_DEF_E2SM_RC_RANFunctionDefinition, NULL, d, buf, cap);
    if (r.encoded >= 0 && (size_t)((r.encoded + 7) / 8) <= cap) n = (long)((r.encoded + 7) / 8);
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_RANFunctionDefinition, d);
  return n;
}

RCC_API int rcc_test_ran_function_definition_summary(const uint8_t *def, size_t len, char *out, size_t cap) {
  E2SM_RC_RANFunctionDefinition_t *d = NULL;
  int rc = -1;
  size_t n = 0;
  asn_dec_rval_t r = aper_decode_complete(NULL, &asn_DEF_E2SM_RC_RANFunctionDefinition, (void **)&d, def, len);
  if (r.code == RC_OK && r.consumed == len && cap > 0) {
    out[0] = 0;
    rc = 0;
    const RANFunctionDefinition_Control_t *ctl = d->ranFunctionDefinition_Control;
    for (int i = 0; ctl && i < ctl->ric_ControlStyle_List.list.count; i++) {
      const RANFunctionDefinition_Control_Item_t *it = ctl->ric_ControlStyle_List.list.array[i];
      for (int j = 0; it->ric_ControlAction_List && j < it->ric_ControlAction_List->list.count; j++) {
        const RANFunctionDefinition_Control_Action_Item_t *a = it->ric_ControlAction_List->list.array[j];
        n += (size_t)snprintf(out + n, n < cap ? cap - n : 0, "%ld/%ld:", it->ric_ControlStyle_Type,
                              a->ric_ControlAction_ID);
        for (int k = 0; a->ran_ControlActionParameters_List && k < a->ran_ControlActionParameters_List->list.count; k++)
          n += (size_t)snprintf(out + n, n < cap ? cap - n : 0, "%s%lu", k ? "," : "",
                                (unsigned long)a->ran_ControlActionParameters_List->list.array[k]->ranParameter_ID);
        n += (size_t)snprintf(out + n, n < cap ? cap - n : 0, ";");
      }
    }
    if (n >= cap) rc = -1;
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_RANFunctionDefinition, d);
  return rc;
}
