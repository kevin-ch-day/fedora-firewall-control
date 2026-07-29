#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace ffc {
enum class OperatingMode { Normal, HostileNetwork };
std::string to_string(OperatingMode mode);
[[nodiscard]] std::optional<OperatingMode> parse_operating_mode(std::string_view value);

class OperatingModeStore {
public:
    [[nodiscard]] OperatingMode load() const;
    [[nodiscard]] bool save(OperatingMode mode, std::string& result) const;
};
} // namespace ffc
