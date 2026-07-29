#include "ffc/credentials.hpp"
#include "ffc/secure_storage.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace ffc {
bool is_valid_ipify_api_key(const std::string& key) {
    return !key.empty() && key.size() <= 128 && std::all_of(key.begin(), key.end(), [](unsigned char character) { return std::isalnum(character) || character == '_' || character == '-'; });
}
std::string IpifyCredentialStore::load() const {
    if (const char* environment_key = std::getenv("FFC_IPIFY_API_KEY"); environment_key != nullptr && is_valid_ipify_api_key(environment_key)) return environment_key;
    std::string error; const auto path = secure_local_path(LocalStorageArea::Config, "ipify.key", false, error); std::string key;
    if (path.empty() || !read_private_file(path, key, error)) return {};
    if (const auto newline = key.find('\n'); newline != std::string::npos) key.erase(newline);
    return is_valid_ipify_api_key(key) ? key : std::string{};
}
bool IpifyCredentialStore::save(const std::string& key, std::string& result) const {
    if (!is_valid_ipify_api_key(key)) { result = "key format is invalid"; return false; }
    std::string error; const auto path = secure_local_path(LocalStorageArea::Config, "ipify.key", true, error); if (path.empty()) { result = error; return false; }
    if (!write_private_file(path, key, false, error)) { result = error; return false; }
    result = path; return true;
}
} // namespace ffc
