#include "ffc/network_manager.hpp"

#include <sstream>

namespace ffc {
std::vector<NetworkDeviceState> parse_network_manager_devices(const std::string& text) {
    std::vector<NetworkDeviceState> devices;
    std::istringstream lines(text); std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line); std::string name, type, state;
        if (!std::getline(fields, name, ':') || !std::getline(fields, type, ':') || !std::getline(fields, state)) continue;
        if (!name.empty()) devices.push_back({name, type, state});
    }
    return devices;
}

NetworkManagerState NetworkManagerInspector::inspect() const {
    const auto result = runner_.run({"nmcli", "--terse", "--fields", "DEVICE,TYPE,STATE", "device", "status"});
    if (!result.success()) return {false, {}, result.stderr_text.empty() ? "nmcli status command failed" : result.stderr_text};
    return {true, parse_network_manager_devices(result.stdout_text), {}};
}
} // namespace ffc
