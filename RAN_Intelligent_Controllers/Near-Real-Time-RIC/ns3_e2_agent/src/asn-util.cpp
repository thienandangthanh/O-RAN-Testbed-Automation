// asn1c helpers (see asn-util.hpp).
#include "asn-util.hpp"

#include <cstdlib>

namespace agent {

bool aper_encode(const asn_TYPE_descriptor_t *td, const void *sptr, Bytes &out, std::string &err) {
  char ebuf[512] = {0};
  size_t elen = sizeof ebuf;
  if (asn_check_constraints(td, sptr, ebuf, &elen) != 0) {
    err = std::string("constraint check failed: ") + ebuf;
    return false;
  }
  out.resize(16384);
  for (;;) {
    asn_enc_rval_t r = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, td, sptr, out.data(), out.size());
    if (r.encoded < 0) {
      err = std::string("APER encode failed at ") + (r.failed_type ? r.failed_type->name : "?");
      return false;
    }
    if ((size_t)r.encoded <= out.size()) {
      out.resize((size_t)r.encoded);
      return true;
    }
    out.resize((size_t)r.encoded);  // buffer too small: retry with the reported size
  }
}

bool aper_decode_clean(const asn_TYPE_descriptor_t *td, void **sptr, const uint8_t *buf, size_t len,
                       std::string &err) {
  *sptr = nullptr;
  asn_dec_rval_t r = asn_decode(nullptr, ATS_ALIGNED_BASIC_PER, td, sptr, buf, len);
  if (r.code != RC_OK || r.consumed != len) {
    err = "decode " + std::string(r.code == RC_OK ? "RC_OK" : r.code == RC_WMORE ? "RC_WMORE" : "RC_FAIL") +
          " consumed " + std::to_string(r.consumed) + " of " + std::to_string(len);
    return false;
  }
  return true;
}

bool set_octets(OCTET_STRING_t *s, const std::string &v) {
  return OCTET_STRING_fromBuf(s, v.data(), (int)v.size()) == 0;
}

OCTET_STRING_t *new_octets(const std::string &v) {
  auto *s = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  if (s && !set_octets(s, v)) {
    free(s);
    return nullptr;
  }
  return s;
}

std::string to_hex(const Bytes &b) {
  static const char *d = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (uint8_t x : b) {
    s += d[x >> 4];
    s += d[x & 15];
  }
  return s;
}

}  // namespace agent
