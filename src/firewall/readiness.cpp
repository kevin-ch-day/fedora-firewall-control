#include "ffc/readiness.hpp"

#include <algorithm>

namespace ffc {
namespace {
bool runtime_matches_permanent(const FirewallState &state) {
    if (!observation_available(state.runtime_zones_status) ||
        !observation_available(state.permanent_zones_status))
        return false;
    if (state.runtime_zones.size() != state.permanent_zones.size())
        return false;
    return std::all_of(state.runtime_zones.begin(), state.runtime_zones.end(),
                       [&state](const auto &zone) {
                           const auto permanent = state.permanent_zones.find(zone.first);
                           return permanent != state.permanent_zones.end() &&
                                  zone_policies_equal(zone.second, permanent->second);
                       });
}

bool active_zone_policy_details_available(const FirewallState &state) {
    return applicable_zone_details_available(state);
}

ReadinessCheck unavailable_check(const std::string &label, const std::string &detail) {
    return {label, CheckLevel::Warn, detail};
}
} // namespace

std::string to_string(const CheckLevel level) {
    switch (level) {
    case CheckLevel::Pass:
        return "PASS";
    case CheckLevel::Warn:
        return "WARN";
    case CheckLevel::Fail:
        return "FAIL";
    case CheckLevel::Info:
        return "INFO";
    }
    return "INFO";
}

std::vector<ReadinessCheck> assess_readiness(const FirewallState &state) {
    std::vector<ReadinessCheck> checks;
    const bool hostile_mode = state.operating_mode == OperatingMode::HostileNetwork;
    checks.push_back({"assessment mode", hostile_mode ? CheckLevel::Pass : CheckLevel::Info,
                      hostile_mode
                          ? "hostile-network criteria active; no firewall setting was changed"
                          : "normal criteria active"});
    checks.push_back({"firewalld installed", state.installed ? CheckLevel::Pass : CheckLevel::Fail,
                      state.installed ? std::string{} : "firewall-cmd was unavailable"});
    checks.push_back({"firewalld active",
                      !observation_available(state.service_state) ? CheckLevel::Warn
                      : state.active                              ? CheckLevel::Pass
                                                                  : CheckLevel::Fail,
                      !observation_available(state.service_state)
                          ? "firewalld state query unavailable"
                      : state.active ? std::string{}
                                     : "firewalld is not running"});
    checks.push_back({"firewalld enabled at boot",
                      !observation_available(state.service_enablement) ? CheckLevel::Warn
                      : state.enabled                                  ? CheckLevel::Pass
                                                                       : CheckLevel::Warn,
                      !observation_available(state.service_enablement)
                          ? "service enablement query unavailable"
                      : state.enabled ? std::string{}
                                      : "not enabled"});
    checks.push_back(!observation_available(state.panic_state)
                         ? unavailable_check("firewalld panic mode", "panic-mode query unavailable")
                         : ReadinessCheck{"firewalld panic mode",
                                          state.panic ? CheckLevel::Fail : CheckLevel::Pass,
                                          state.panic ? "panic mode is active" : "off"});
    checks.push_back(
        !observation_available(state.permanent_config)
            ? unavailable_check("permanent configuration valid",
                                "firewall-cmd --check-config unavailable")
            : ReadinessCheck{"permanent configuration valid",
                             state.permanent_config_valid ? CheckLevel::Pass : CheckLevel::Fail,
                             state.permanent_config_valid
                                 ? std::string{}
                                 : "firewall-cmd --check-config did not pass"});
    checks.push_back(
        !observation_available(state.default_zone_status)
            ? unavailable_check("default zone set", "default-zone query unavailable")
            : ReadinessCheck{"default zone set",
                             state.default_zone.empty() ? CheckLevel::Fail : CheckLevel::Pass,
                             state.default_zone});

    const bool active_details_available = active_zone_policy_details_available(state);
    bool forwarding = false;
    bool forwarding_path = false;
    bool masquerade = false;
    bool exposure = false;
    bool permissive_target = false;
    bool forward_ports = false;
    if (active_details_available) {
        for (const auto &[zone, config] : state.runtime_zones) {
            if (!is_zone_applicable(state, zone))
                continue;
            forwarding = forwarding || config.forward;
            forwarding_path =
                forwarding_path || (config.forward && active_zone_member_count(state, zone) > 1U);
            masquerade = masquerade || config.masquerade;
            exposure = exposure || !config.services.empty() || !config.ports.empty() ||
                       !config.protocols.empty() || !config.source_ports.empty() ||
                       !config.rich_rules.empty();
            permissive_target = permissive_target || config.target == "ACCEPT";
            forward_ports = forward_ports || !config.forward_ports.empty();
        }
    }

    checks.push_back({"NetworkManager status",
                      state.network_manager.available ? CheckLevel::Pass : CheckLevel::Warn,
                      state.network_manager.available ? "available" : "nmcli status unavailable"});
    bool connected_wifi = false;
    for (const auto &device : state.network_manager.devices)
        connected_wifi =
            connected_wifi || (device.type == "wifi" && device.state.rfind("connected", 0) == 0);
    checks.push_back({"untrusted-transport review",
                      connected_wifi ? CheckLevel::Warn : CheckLevel::Info,
                      connected_wifi ? "Wi-Fi is connected; validate its zone and exposure"
                                     : "transport alone cannot identify a venue or attacker"});
    checks.push_back({"VPN tunnel awareness",
                      !state.vpn.interface_scan_available          ? CheckLevel::Warn
                      : state.vpn.active_tunnel_interfaces.empty() ? CheckLevel::Info
                                                                   : CheckLevel::Pass,
                      !state.vpn.interface_scan_available ? "local tunnel scan unavailable"
                      : state.vpn.active_tunnel_interfaces.empty()
                          ? "no detected tunnel-like interface"
                          : "detected tunnel-like interface; route use is not verified"});

    if (!observation_available(state.active_zones_status)) {
        checks.push_back(
            unavailable_check("active interface assignments", "active-zone query unavailable"));
    } else if (state.active_zone_interfaces.empty() && state.active_zone_sources.empty()) {
        checks.push_back({"active interface assignments", CheckLevel::Warn,
                          "no active zone assignments reported"});
    } else if (state.active_zone_interfaces.empty()) {
        checks.push_back({"active interface assignments", CheckLevel::Info,
                          "only source-based active zones reported"});
    } else {
        checks.push_back({"active interface assignments", CheckLevel::Pass,
                          "inspect NetworkManager bindings separately"});
    }
    bool unclassified_connected_device = false;
    if (state.network_manager.available && observation_available(state.active_zones_status)) {
        for (const auto &device : state.network_manager.devices) {
            if (!is_connected_transport_device(device))
                continue;
            bool classified = false;
            for (const auto &[zone, interfaces] : state.active_zone_interfaces) {
                (void)zone;
                classified = classified || std::find(interfaces.begin(), interfaces.end(),
                                                     device.interface_name) != interfaces.end();
            }
            unclassified_connected_device = unclassified_connected_device || !classified;
        }
    }
    checks.push_back(
        !state.network_manager.available || !observation_available(state.active_zones_status)
            ? unavailable_check("connected devices assigned to active zones",
                                "NetworkManager or active-zone evidence unavailable")
            : ReadinessCheck{"connected devices assigned to active zones",
                             unclassified_connected_device ? CheckLevel::Warn : CheckLevel::Pass,
                             unclassified_connected_device
                                 ? "a connected NetworkManager device has no active-zone binding"
                                 : "all observed connected devices are classified"});
    checks.push_back(
        !observation_available(state.active_zones_status)
            ? unavailable_check("active source bindings", "active-zone query unavailable")
            : ReadinessCheck{
                  "active source bindings",
                  state.active_zone_sources.empty() ? CheckLevel::Pass : CheckLevel::Warn,
                  state.active_zone_sources.empty() ? "none" : "review source-based trust"});

    const auto listener_exposure = summarize_listener_exposure(state.sockets);
    checks.push_back({"TCP/UDP non-multicast listener exposure",
                      !state.sockets.available                          ? CheckLevel::Warn
                      : listener_exposure.logical_network_services == 0 ? CheckLevel::Pass
                      : hostile_mode                                    ? CheckLevel::Fail
                                                                        : CheckLevel::Warn,
                      !state.sockets.available ? "socket scan unavailable"
                      : listener_exposure.logical_network_services == 0
                          ? "none observed; SCTP, DCCP, raw, and protocol sockets are not collected"
                          : std::to_string(listener_exposure.logical_network_services) +
                                " logical service(s) across " +
                                std::to_string(listener_exposure.network_reachable_bindings) +
                                " non-multicast binding(s)"});
    checks.push_back({"multicast listener exposure",
                      !state.sockets.available                              ? CheckLevel::Warn
                      : listener_exposure.multicast_only_bindings == 0       ? CheckLevel::Info
                      : hostile_mode                                         ? CheckLevel::Warn
                                                                             : CheckLevel::Info,
                      !state.sockets.available ? "socket scan unavailable"
                      : listener_exposure.multicast_only_bindings == 0
                          ? "none observed in the TCP/UDP listener query"
                          : std::to_string(listener_exposure.multicast_only_bindings) +
                                " binding(s); local-segment discovery traffic remains possible"});
    checks.push_back({"kernel drop/reject log signals",
                      !state.security_signals.kernel_journal_available           ? CheckLevel::Warn
                      : state.security_signals.kernel_drop_or_reject_events == 0 ? CheckLevel::Pass
                                                                                 : CheckLevel::Warn,
                      !state.security_signals.kernel_journal_available
                          ? state.security_signals.kernel_journal_status == JournalQueryStatus::Partial
                                ? "at least " +
                                      std::to_string(state.security_signals.kernel_drop_or_reject_events) +
                                      " event(s); bounded journal view may be truncated"
                                : "journal unavailable"
                      : state.security_signals.kernel_drop_or_reject_events == 0
                          ? "none in the last 24h"
                          : std::to_string(state.security_signals.kernel_drop_or_reject_events) +
                                " event(s); review, do not attribute"});

    const std::string unavailable_policy_detail =
        "applicable-zone or runtime policy collection unavailable or incomplete";
    checks.push_back(
        !active_details_available
            ? unavailable_check("inbound services, ports, and protocols", unavailable_policy_detail)
            : ReadinessCheck{"inbound services, ports, and protocols",
                             exposure ? (hostile_mode ? CheckLevel::Fail : CheckLevel::Warn)
                                      : CheckLevel::Pass,
                             exposure ? "review configured exposure or rich rules" : "none"});
    const auto applicable_rich_rules = [&state]() {
        std::size_t count = 0;
        for (const auto &[zone, config] : state.runtime_zones)
            if (is_zone_applicable(state, zone))
                count += config.rich_rules.size();
        return count;
    }();
    checks.push_back(!active_details_available
                         ? unavailable_check("active rich rules", unavailable_policy_detail)
                         : applicable_rich_rules == 0
                               ? ReadinessCheck{"active rich rules", CheckLevel::Pass, "none"}
                               : ReadinessCheck{"active rich rules",
                                                hostile_mode ? CheckLevel::Fail : CheckLevel::Warn,
                                                std::to_string(applicable_rich_rules) +
                                                    " rule(s); semantics are not fully parsed"});
    checks.push_back(!active_details_available
                         ? unavailable_check("active zone target", unavailable_policy_detail)
                         : ReadinessCheck{"active zone target",
                                          permissive_target ? CheckLevel::Fail : CheckLevel::Pass,
                                          permissive_target
                                              ? "ACCEPT target trusts unmatched traffic"
                                              : "no active ACCEPT target"});
    checks.push_back(!active_details_available
                         ? unavailable_check("active forward ports", unavailable_policy_detail)
                         : ReadinessCheck{"active forward ports",
                                          forward_ports ? CheckLevel::Warn : CheckLevel::Pass,
                                          forward_ports ? "review forwarded traffic" : "none"});
    checks.push_back(
        !active_details_available
            ? unavailable_check("intra-zone forwarding", unavailable_policy_detail)
            : ReadinessCheck{
                  "intra-zone forwarding",
                  !forwarding       ? CheckLevel::Pass
                  : forwarding_path ? (hostile_mode ? CheckLevel::Fail : CheckLevel::Warn)
                                    : CheckLevel::Info,
                  !forwarding ? "disabled"
                  : forwarding_path
                      ? "active zone has multiple members that can forward between each other"
                      : "configured, but no active zone has multiple interface/source members"});
    checks.push_back(!active_details_available
                         ? unavailable_check("masquerading disabled", unavailable_policy_detail)
                         : ReadinessCheck{"masquerading disabled",
                                          masquerade
                                              ? (hostile_mode ? CheckLevel::Fail : CheckLevel::Warn)
                                              : CheckLevel::Pass,
                                          {}});
    checks.push_back(
        !observation_available(state.active_policies_status)
            ? unavailable_check("active firewalld policies", "policy inventory unavailable")
        : state.active_policies.empty()
            ? ReadinessCheck{"active firewalld policies", CheckLevel::Pass, "none"}
            : ReadinessCheck{"active firewalld policies", CheckLevel::Warn,
                             std::to_string(state.active_policies.size()) +
                                 " active policy name(s); policy details are not yet assessed"});
    checks.push_back(
        active_details_available
            ? ReadinessCheck{"zone policy coverage", CheckLevel::Info,
                             "rich-rule semantics, ICMP blocks, helpers, priorities, and direct rules are not yet assessed"}
            : unavailable_check("zone policy coverage", unavailable_policy_detail));
    checks.push_back(
        !observation_available(state.runtime_zones_status) ||
                !observation_available(state.permanent_zones_status)
            ? unavailable_check("permanent/runtime state aligned",
                                "runtime or permanent policy collection unavailable")
            : ReadinessCheck{"permanent/runtime state aligned",
                             runtime_matches_permanent(state) ? CheckLevel::Pass : CheckLevel::Warn,
                             runtime_matches_permanent(state) ? std::string{}
                                                              : "runtime differs from permanent"});
    if (!state.errors.empty())
        checks.push_back({"firewalld collection diagnostics", CheckLevel::Warn,
                          std::to_string(state.errors.size()) + " collection issue(s) reported"});
    return checks;
}
} // namespace ffc
