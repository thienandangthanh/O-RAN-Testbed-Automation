/*
 * rc-codec: the E2SM-RC v2.0 control-path codec of the ns3-e2-agent.
 *
 * Built as librc_codec.so from the generated E2SM-RC code that ric-app-rc
 * itself ships (rc@a2282ee e2sm/lib + e2sm/headers, the code rc encodes its
 * RIC CONTROL requests with). Every asn1c symbol is hidden; only the rcc_*
 * functions below are exported, so this asn1c runtime never clashes with
 * NIST's E2AP + E2SM-KPM asn1c linked into the agent.
 */
#ifndef NS3_E2_AGENT_RC_CODEC_H
#define NS3_E2_AGENT_RC_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One decoded RIC CONTROL request (header Format 1 + message Format 1). */
typedef struct rcc_control {
  long style;                /* ric-Style-Type */
  long action;               /* ric-ControlAction-ID */
  /* 1 when the UE ID is en-gNB-UEID {m-eNB-UE-X2AP-ID, globalENB-ID {pLMN-Identity, macro-eNB-ID}} and neither it
   * nor the header carries an optional member (ric-ControlDecision, m-eNB-UE-X2AP-ID-Extension, gNB-CU-UE-F1AP-ID,
   * gNB-CU-CP-UE-E1AP-ID-List, ran-UEID); then the three fields below are set. Otherwise 0 and ueIdErr says why. */
  int enGnbUeId;
  char ueIdErr[96];
  uint32_t mEnbUeX2apId;     /* ENB-UE-X2AP-ID INTEGER (0..4095) */
  uint8_t globalEnbPlmn[3];  /* globalENB-ID pLMN-Identity */
  uint32_t macroEnbId;       /* globalENB-ID macro-eNB-ID, BIT STRING (SIZE(20)) */
  uint8_t targetOctets[16];  /* RAN parameter 4 (NR CGI) valueOctS under 1/2/3, checked by rcc_decode_nr_cgi_strict */
  size_t targetLen;
} rcc_control;

/*
 * Decodes the E2SM-RC control header and message (APER). Returns 0 when both
 * decode cleanly (RC_OK, every octet consumed), the header is Format 1 and the
 * message is Format 1 carrying RAN parameter 1 > 2 > 3 > 4 (NR CGI) as an octet
 * string; style, action, the UE ID fields (enGnbUeId) and the target are then
 * filled in. Any UE ID CHOICE decodes, so the caller judges the style and
 * action before the UE ID. Otherwise returns -1 and writes the reason to err.
 */
int rcc_decode_control(const uint8_t *hdr, size_t hdrLen, const uint8_t *msg, size_t msgLen,
                       rcc_control *out, char *err, size_t errLen);

/*
 * Strict NR CGI (E2SM common NR-CGI, APER, the value of RAN parameter 4): exactly 9 octets that decode cleanly and
 * re-encode to the same 9 octets, so a value with nonzero padding bits is refused. On success writes the 3 PLMN
 * octets and the 36-bit NR Cell Identity and returns 0; otherwise -1 with the reason in err.
 */
int rcc_decode_nr_cgi_strict(const uint8_t *buf, size_t len, uint8_t plmn[3], uint64_t *nci, char *err,
                             size_t errLen);

/*
 * E2SM-RC RAN Function Definition of RAN function 3 (APER), from rc-codec-ran-function-definition.c: CONTROL
 * Style 5 action 3 only, with RAN parameters 1-4. Returns the number of octets written to buf, or -1.
 * rcc_ran_function_oid() is the E2SM-RC OID announced with it.
 */
long rcc_encode_ran_function_definition(uint8_t *buf, size_t cap);
const char *rcc_ran_function_oid(void);

/*
 * Encodes E2SM-RC-ControlOutcome Format 1 with an empty ranP-List into buf.
 * Returns the number of octets, or -1 if cap is too small.
 */
long rcc_encode_outcome_format1_empty(uint8_t *buf, size_t cap);

/* Test support (tests/rc-control-test.cpp builds request variants from the
 * committed fixture): decode, change one field, re-encode. Return the new
 * length, or -1. */
long rcc_test_reencode_header(const uint8_t *hdr, size_t hdrLen, long style, long action, uint8_t *out, size_t cap);
long rcc_test_reencode_target(const uint8_t *msg, size_t msgLen, const uint8_t *target, size_t targetLen,
                              uint8_t *out, size_t cap);
/* Test support: the CONTROL styles of a RAN Function Definition as "<style>/<action>:<id>,<id>,...;" per action, in
 * order (every RAN parameter ID of the action's list). Returns 0, or -1 if it does not decode cleanly. */
int rcc_test_ran_function_definition_summary(const uint8_t *def, size_t len, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
