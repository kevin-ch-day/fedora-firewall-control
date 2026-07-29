#include "ffc/operating_mode.hpp"
#include "ffc/secure_storage.hpp"

#include <filesystem>

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
OperatingModeLoadResult OperatingModeStore::load() const {
    std::string error;
    const auto path = secure_local_path(LocalStorageArea::Config, "mode", false, error);
    std::string value;
    if (path.empty())
        return {OperatingMode::HostileNetwork, OperatingModeLoadStatus::Invalid,
                "could not resolve assessment-mode storage: " + error};
    std::error_code exists_error;
    if (!std::filesystem::exists(path, exists_error)) {
        if (!exists_error)
            return {};
        return {OperatingMode::HostileNetwork, OperatingModeLoadStatus::Invalid,
                "could not inspect assessment-mode storage: " + exists_error.message()};
    }
    if (!read_private_file(path, value, error))
        return {OperatingMode::HostileNetwork, OperatingModeLoadStatus::Invalid,
                "could not read assessment-mode storage: " + error};
    if (const auto newline = value.find('\n'); newline != std::string::npos)
        value.erase(newline);
    if (const auto mode = parse_operating_mode(value); mode.has_value())
        return {*mode, OperatingModeLoadStatus::Available, {}};
    return {OperatingMode::HostileNetwork, OperatingModeLoadStatus::Invalid,
            "assessment-mode storage contains an unrecognized value"};
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
