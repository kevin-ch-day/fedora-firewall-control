#pragma once

#include <string>

namespace ffc {
enum class OperatingMode { Normal, HostileNetwork };
std::string to_string(OperatingMode mode);
bool parse_operating_mode(const std::string& value, OperatingMode& mode);

class OperatingModeStore {
public:
    [[nodiscard]] OperatingMode load() const;
    [[nodiscard]] bool save(OperatingMode mode, std::string& result) const;
};
} // namespace ffc
