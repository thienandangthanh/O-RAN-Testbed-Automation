// Minimal SHA-256 (FIPS 180-4) so the agent can fingerprint its metric map
// without a crypto library. Not used for anything security-relevant.
#ifndef NS3_E2_AGENT_SHA256_HPP
#define NS3_E2_AGENT_SHA256_HPP

#include <string>

namespace agent {

// Returns the lowercase hex SHA-256 of `data`.
std::string sha256_hex(const std::string &data);

}  // namespace agent

#endif
