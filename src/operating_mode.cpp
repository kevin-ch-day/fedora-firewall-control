#include "ffc/operating_mode.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

namespace ffc {
std::string to_string(OperatingMode mode) { return mode == OperatingMode::HostileNetwork ? "DEF CON / POSSIBLE HOSTILE" : "NORMAL"; }
bool parse_operating_mode(const std::string& value, OperatingMode& mode) {
    if (value == "normal") { mode = OperatingMode::Normal; return true; }
    if (value == "hostile") { mode = OperatingMode::HostileNetwork; return true; }
    return false;
}
namespace {
std::string config_path(bool create, std::string& error) {
    const char* config_home = std::getenv("XDG_CONFIG_HOME"); const char* home = std::getenv("HOME");
    std::filesystem::path directory;
    if (config_home != nullptr && *config_home != '\0') directory = config_home;
    else if (home != nullptr && *home != '\0') directory = std::filesystem::path(home) / ".config";
    else { error = "HOME and XDG_CONFIG_HOME are unavailable"; return {}; }
    directory /= "fedora-firewall-control";
    if (create) { std::error_code code; std::filesystem::create_directories(directory, code); if (code) { error = code.message(); return {}; } chmod(directory.c_str(), S_IRWXU); }
    return (directory / "mode").string();
}
}
OperatingMode OperatingModeStore::load() const {
    std::string error; const auto path = config_path(false, error); std::ifstream input(path); std::string value; OperatingMode mode;
    return input && std::getline(input, value) && parse_operating_mode(value, mode) ? mode : OperatingMode::Normal;
}
bool OperatingModeStore::save(OperatingMode mode, std::string& result) const {
    std::string error; const auto path = config_path(true, error); if (path.empty()) { result = error; return false; }
    std::ofstream output(path); if (!output) { result = "could not write mode setting"; return false; }
    output << (mode == OperatingMode::HostileNetwork ? "hostile" : "normal") << '\n'; output.close(); chmod(path.c_str(), S_IRUSR | S_IWUSR); result = path; return true;
}
} // namespace ffc
