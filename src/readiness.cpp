#include "ffc/readiness.hpp"

#include <algorithm>

namespace ffc {
std::string to_string(CheckLevel level) {
    switch (level) { case CheckLevel::Pass: return "PASS"; case CheckLevel::Warn: return "WARN"; case CheckLevel::Fail: return "FAIL"; case CheckLevel::Info: return "INFO"; }
    return "INFO";
}

std::vector<ReadinessCheck> assess_readiness(const FirewallState& state) {
    std::vector<ReadinessCheck> checks;
    const bool hostile_mode = state.operating_mode == OperatingMode::HostileNetwork;
    checks.push_back({"assessment mode", hostile_mode ? CheckLevel::Pass : CheckLevel::Info, hostile_mode ? "hostile-network criteria active; no firewall setting was changed" : "normal criteria active"});
    checks.push_back({"firewalld installed", state.installed ? CheckLevel::Pass : CheckLevel::Fail, {}});
    checks.push_back({"firewalld active", state.active ? CheckLevel::Pass : CheckLevel::Fail, {}});
    checks.push_back({"firewalld enabled at boot", state.enabled ? CheckLevel::Pass : CheckLevel::Warn, {}});
    checks.push_back({"firewalld panic mode", state.panic ? CheckLevel::Fail : CheckLevel::Pass, state.panic ? "panic mode is active" : "off"});
    checks.push_back({"permanent configuration valid", !state.permanent_config_checked ? CheckLevel::Warn : state.permanent_config_valid ? CheckLevel::Pass : CheckLevel::Fail,
                      state.permanent_config_valid ? std::string{} : "firewall-cmd --check-config did not pass"});
    checks.push_back({"default zone set", state.default_zone.empty() ? CheckLevel::Fail : CheckLevel::Pass, state.default_zone});
    bool forwarding = false, masquerade = false, exposure = false, aligned = true, permissive_target = false, forward_ports = false;
    for (const auto& [zone, config] : state.runtime_zones) {
        forwarding = forwarding || config.forward; masquerade = masquerade || config.masquerade;
        if (state.active_zone_interfaces.contains(zone)) {
            exposure = exposure || !config.services.empty() || !config.ports.empty();
            permissive_target = permissive_target || config.target == "ACCEPT";
            forward_ports = forward_ports || !config.forward_ports.empty();
        }
        const auto it = state.permanent_zones.find(zone); aligned = aligned && it != state.permanent_zones.end() && zone_configurations_equal(config, it->second);
    }
    checks.push_back({"NetworkManager status", state.network_manager.available ? CheckLevel::Pass : CheckLevel::Warn,
                      state.network_manager.available ? "available" : "nmcli status unavailable"});
    bool connected_wifi = false;
    for (const auto& device : state.network_manager.devices) connected_wifi = connected_wifi || (device.type == "wifi" && device.state.rfind("connected", 0) == 0);
    checks.push_back({"untrusted-transport review", connected_wifi ? CheckLevel::Warn : CheckLevel::Info,
                      connected_wifi ? "Wi-Fi is connected; validate its zone and exposure" : "transport alone cannot identify a venue or attacker"});
    checks.push_back({"VPN tunnel awareness", !state.vpn.interface_scan_available ? CheckLevel::Warn : state.vpn.active_tunnel_interfaces.empty() ? CheckLevel::Info : CheckLevel::Pass,
                      !state.vpn.interface_scan_available ? "local tunnel scan unavailable" : state.vpn.active_tunnel_interfaces.empty() ? "no active tunnel detected" : "do not automatically reassign tunnel interfaces"});
    checks.push_back({"active interfaces classified", state.active_zone_interfaces.empty() ? CheckLevel::Warn : CheckLevel::Pass,
                      state.active_zone_interfaces.empty() ? "no active zone assignments reported" : "inspect NetworkManager bindings separately"});
    bool unclassified_connected_device = false;
    for (const auto& device : state.network_manager.devices) {
        if (device.type == "loopback") continue;
        if (device.state.rfind("connected", 0) != 0) continue;
        bool classified = false;
        for (const auto& [zone, interfaces] : state.active_zone_interfaces) {
            (void)zone;
            classified = classified || std::find(interfaces.begin(), interfaces.end(), device.interface_name) != interfaces.end();
        }
        unclassified_connected_device = unclassified_connected_device || !classified;
    }
    checks.push_back({"connected devices assigned to active zones", unclassified_connected_device ? CheckLevel::Warn : CheckLevel::Pass,
                      unclassified_connected_device ? "a connected NetworkManager device has no active-zone binding" : "all observed connected devices are classified"});
    checks.push_back({"active source bindings", state.active_zone_sources.empty() ? CheckLevel::Pass : CheckLevel::Warn,
                      state.active_zone_sources.empty() ? "none" : "review source-based trust"});
    size_t network_listeners = 0;
    for (const auto& listener : state.sockets.listeners) if (!listener.loopback_only) ++network_listeners;
    checks.push_back({"network-reachable listening sockets", !state.sockets.available ? CheckLevel::Warn : network_listeners == 0 ? CheckLevel::Pass : hostile_mode ? CheckLevel::Fail : CheckLevel::Warn,
                      !state.sockets.available ? "socket scan unavailable" : network_listeners == 0 ? "none" : std::to_string(network_listeners) + " socket(s) listening beyond loopback"});
    checks.push_back({"kernel drop/reject log signals", !state.security_signals.kernel_journal_available ? CheckLevel::Warn : state.security_signals.kernel_drop_or_reject_events == 0 ? CheckLevel::Pass : CheckLevel::Warn,
                      !state.security_signals.kernel_journal_available ? "journal unavailable" : state.security_signals.kernel_drop_or_reject_events == 0 ? "none in the last 24h" : std::to_string(state.security_signals.kernel_drop_or_reject_events) + " event(s); review, do not attribute"});
    checks.push_back({"inbound services or explicit ports", exposure ? (hostile_mode ? CheckLevel::Fail : CheckLevel::Warn) : CheckLevel::Pass, exposure ? "review configured exposure" : "none"});
    checks.push_back({"active zone target", permissive_target ? CheckLevel::Fail : CheckLevel::Pass, permissive_target ? "ACCEPT target trusts unmatched traffic" : "no active ACCEPT target"});
    checks.push_back({"active forward ports", forward_ports ? CheckLevel::Warn : CheckLevel::Pass, forward_ports ? "review forwarded traffic" : "none"});
    checks.push_back({"forwarding disabled", forwarding ? (hostile_mode ? CheckLevel::Fail : CheckLevel::Warn) : CheckLevel::Pass, {}});
    checks.push_back({"masquerading disabled", masquerade ? (hostile_mode ? CheckLevel::Fail : CheckLevel::Warn) : CheckLevel::Pass, {}});
    checks.push_back({"permanent/runtime state aligned", aligned ? CheckLevel::Pass : CheckLevel::Warn,
                      aligned ? std::string{} : "runtime differs from permanent"});
    return checks;
}
} // namespace ffc
