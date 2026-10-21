// Thin helpers over NIST's asn1c runtime (e2sim/asn1c): constraint-checked
// APER encoding into a byte vector, clean decoding, and string fields.
#ifndef NS3_E2_AGENT_ASN_UTIL_HPP
#define NS3_E2_AGENT_ASN_UTIL_HPP

#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "constr_TYPE.h"
}

namespace agent {

using Bytes = std::vector<uint8_t>;

// asn_check_constraints, then ALIGNED-BASIC-PER encode. False + err on failure.
bool aper_encode(const asn_TYPE_descriptor_t *td, const void *sptr, Bytes &out, std::string &err);

// ALIGNED-BASIC-PER decode that is "clean": RC_OK and every octet consumed.
// On success *sptr owns a new structure (free with ASN_STRUCT_FREE).
bool aper_decode_clean(const asn_TYPE_descriptor_t *td, void **sptr, const uint8_t *buf, size_t len,
                       std::string &err);

// Sets an OCTET STRING / PrintableString field (allocates its buffer).
bool set_octets(OCTET_STRING_t *s, const std::string &v);

// Allocates a new OCTET STRING / PrintableString with the given contents.
OCTET_STRING_t *new_octets(const std::string &v);

// Lowercase hex of a byte vector.
std::string to_hex(const Bytes &b);

}  // namespace agent

#endif
