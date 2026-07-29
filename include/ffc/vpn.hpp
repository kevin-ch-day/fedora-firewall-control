#pragma once

#include "ffc/command_runner.hpp"

#include <string>
#include <vector>

namespace ffc {
struct VpnState {
    bool nordvpn_installed{false};
    bool interface_scan_available{false};
    std::vector<std::string> active_tunnel_interfaces;
    std::string diagnostic;
};

std::vector<std::string> parse_vpn_tunnel_interfaces(const std::string& ip_link_output);

// Detects local VPN capability and tunnel interfaces only. It never invokes
// VPN connect/disconnect commands and does not expose a provider endpoint.
class VpnInspector {
public:
    explicit VpnInspector(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] VpnState inspect() const;

private:
    const CommandRunner& runner_;
};
} // namespace ffc
