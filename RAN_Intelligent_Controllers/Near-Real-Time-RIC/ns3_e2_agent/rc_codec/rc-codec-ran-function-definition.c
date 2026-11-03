/* E2SM-RC RAN Function Definition of the agent's RAN function 3 (see rc-codec.h). Names and IDs are those of O-RAN
 * E2SM-RC v03.00 (identical in v01.03): §7.2 (RAN Function name), §7.6.4 (CONTROL Service Style 3 "Connected Mode
 * Mobility Control", action 1 "Handover Control", RAN parameters §8.4.4.1), §7.6.6 (Style 5 "Dual Connectivity
 * Control", action 3 "DC PSCell Change control", RAN parameters §8.4.6.3). Both styles use Control Header, Message
 * and Outcome Format 1 (§7.6.4.2-5, §7.6.6.2-5); no Call Process ID format (no INSERT service). Only the
 * parameters the agent reads are listed: 1, its CHOICE Target Cell (2), NR Cell (3) and NR CGI (4). */
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
    {3, "Connected Mode Mobility Control", 1, "Handover Control", "Target Primary Cell ID"},
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
