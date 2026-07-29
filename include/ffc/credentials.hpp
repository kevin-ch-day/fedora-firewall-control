#pragma once

#include <string>

namespace ffc {
bool is_valid_ipify_api_key(const std::string& key);

class IpifyCredentialStore {
public:
    [[nodiscard]] std::string load() const;
    [[nodiscard]] bool save(const std::string& key, std::string& result) const;
};
} // namespace ffc
