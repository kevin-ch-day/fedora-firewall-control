#include "ffc/operating_mode.hpp"
#include "ffc/secure_storage.hpp"

namespace ffc {
std::string to_string(OperatingMode mode) {
    return mode == OperatingMode::HostileNetwork ? "DEF CON / POSSIBLE HOSTILE" : "NORMAL";
}
std::optional<OperatingMode> parse_operating_mode(const std::string_view value) {
    if (value == "normal")
        return OperatingMode::Normal;
    if (value == "hostile")
        return OperatingMode::HostileNetwork;
    return std::nullopt;
}
OperatingMode OperatingModeStore::load() const {
    std::string error;
    const auto path = secure_local_path(LocalStorageArea::Config, "mode", false, error);
    std::string value;
    if (path.empty() || !read_private_file(path, value, error))
        return OperatingMode::Normal;
    if (const auto newline = value.find('\n'); newline != std::string::npos)
        value.erase(newline);
    return parse_operating_mode(value).value_or(OperatingMode::Normal);
}
bool OperatingModeStore::save(OperatingMode mode, std::string &result) const {
    std::string error;
    const auto path = secure_local_path(LocalStorageArea::Config, "mode", true, error);
    if (path.empty()) {
        result = error;
        return false;
    }
    if (!write_private_file(path, mode == OperatingMode::HostileNetwork ? "hostile" : "normal",
                            false, error)) {
        result = error;
        return false;
    }
    result = path;
    return true;
}
} // namespace ffc
