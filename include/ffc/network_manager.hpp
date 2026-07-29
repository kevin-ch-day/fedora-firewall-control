#pragma once

#include "ffc/command_runner.hpp"

#include <string>
#include <vector>

namespace ffc {
struct NetworkDeviceState {
    std::string interface_name;
    std::string type;
    std::string state;
};

struct NetworkManagerState {
    bool available{false};
    std::vector<NetworkDeviceState> devices;
    std::string diagnostic;
};

std::vector<NetworkDeviceState> parse_network_manager_devices(const std::string& text);

// Read-only NetworkManager adapter. It intentionally requests no connection
// names or Wi-Fi SSIDs, which are unnecessary for firewall classification.
class NetworkManagerInspector {
public:
    explicit NetworkManagerInspector(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] NetworkManagerState inspect() const;

private:
    const CommandRunner& runner_;
};
} // namespace ffc
