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
  uint64_t amfUeNgapId;      /* UEID gNB-UEID amf-UE-NGAP-ID */
  uint8_t targetOctets[16];  /* RAN parameter 4 (NR CGI) valueOctS under 1/2/3 */
  size_t targetLen;
} rcc_control;

/*
 * Decodes the E2SM-RC control header and message (APER). Returns 0 when both
 * decode cleanly (RC_OK, every octet consumed), the header is Format 1 with a
 * gNB-UEID, and the message is Format 1 carrying Target Primary Cell ID (1) >
 * CHOICE Target Cell (2) > NR Cell (3) > NR CGI (4) as an octet string.
 * Otherwise returns -1 and writes the reason to err.
 */
int rcc_decode_control(const uint8_t *hdr, size_t hdrLen, const uint8_t *msg, size_t msgLen,
                       rcc_control *out, char *err, size_t errLen);

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

#ifdef __cplusplus
}
#endif

#endif
