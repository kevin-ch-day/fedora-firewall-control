#pragma once

#include "ffc/firewall_backend.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/operating_mode.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/vpn.hpp"

namespace ffc {
// Composes the independent, read-only inspectors into one coherent posture
// snapshot. This is the sole owner of cross-inspector availability notices.
class PostureInspector {
public:
    PostureInspector(const FirewallBackend& firewall, const NetworkManagerInspector& network_manager, const VpnInspector& vpn, const SocketInspector& sockets, const SecuritySignalsInspector& security_signals, const OperatingModeStore& operating_mode)
        : firewall_(firewall), network_manager_(network_manager), vpn_(vpn), sockets_(sockets), security_signals_(security_signals), operating_mode_(operating_mode) {}

    [[nodiscard]] FirewallState inspect() const;

private:
    const FirewallBackend& firewall_;
    const NetworkManagerInspector& network_manager_;
    const VpnInspector& vpn_;
    const SocketInspector& sockets_;
    const SecuritySignalsInspector& security_signals_;
    const OperatingModeStore& operating_mode_;
};
} // namespace ffc
