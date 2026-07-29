#include "ffc/credentials.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

namespace ffc {
bool is_valid_ipify_api_key(const std::string& key) {
    return !key.empty() && key.size() <= 128 && std::all_of(key.begin(), key.end(), [](unsigned char character) { return std::isalnum(character) || character == '_' || character == '-'; });
}
namespace {
std::string credential_path(bool create, std::string& error) {
    const char* config_home = std::getenv("XDG_CONFIG_HOME"); const char* home = std::getenv("HOME"); std::filesystem::path directory;
    if (config_home != nullptr && *config_home != '\0') directory = config_home;
    else if (home != nullptr && *home != '\0') directory = std::filesystem::path(home) / ".config";
    else { error = "HOME and XDG_CONFIG_HOME are unavailable"; return {}; }
    directory /= "fedora-firewall-control";
    if (create) { std::error_code code; std::filesystem::create_directories(directory, code); if (code) { error = code.message(); return {}; } chmod(directory.c_str(), S_IRWXU); }
    return (directory / "ipify.key").string();
}
}
std::string IpifyCredentialStore::load() const {
    if (const char* environment_key = std::getenv("FFC_IPIFY_API_KEY"); environment_key != nullptr && is_valid_ipify_api_key(environment_key)) return environment_key;
    std::string error; const auto path = credential_path(false, error); std::ifstream input(path); std::string key; return input && std::getline(input, key) && is_valid_ipify_api_key(key) ? key : std::string{};
}
bool IpifyCredentialStore::save(const std::string& key, std::string& result) const {
    if (!is_valid_ipify_api_key(key)) { result = "key format is invalid"; return false; }
    std::string error; const auto path = credential_path(true, error); if (path.empty()) { result = error; return false; }
    std::ofstream output(path); if (!output) { result = "could not write credential file"; return false; }
    output << key << '\n'; output.close(); chmod(path.c_str(), S_IRUSR | S_IWUSR); result = path; return true;
}
} // namespace ffc
