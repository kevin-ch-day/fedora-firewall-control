#include "ffc/posture_renderer.hpp"

#include "ffc/port_intelligence.hpp"
#include "ffc/readiness.hpp"
#include "ffc/threat_assessment.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>

namespace ffc {
namespace {
std::string annotated_port_list(const std::vector<std::string> &ports) {
    if (ports.empty())
        return "none";
    std::string result;
    for (const auto &port : ports)
        result += (result.empty() ? "" : ", ") + port + " (" +
                  port_intel_label(identify_port_spec(port)) + ")";
    return result;
}

struct ExposureCounts {
    std::size_t services{0};
    std::size_t ports{0};
    std::size_t protocols{0};
    std::size_t source_ports{0};
    std::size_t rich_rules{0};
    std::size_t forward_ports{0};
    bool forwarding{false};
    bool masquerade{false};
};

ExposureCounts active_exposure_counts(const FirewallState &state) {
    ExposureCounts counts;
    for (const auto &[zone_name, zone] : state.runtime_zones) {
        if (!is_zone_applicable(state, zone_name))
            continue;
        counts.services += zone.services.size();
        counts.ports += zone.ports.size();
        counts.protocols += zone.protocols.size();
        counts.source_ports += zone.source_ports.size();
        counts.rich_rules += zone.rich_rules.size();
        counts.forward_ports += zone.forward_ports.size();
        counts.forwarding = counts.forwarding || zone.forward;
        counts.masquerade = counts.masquerade || zone.masquerade;
    }
    return counts;
}

std::pair<std::string, std::string> physical_interface_and_zone(const FirewallState& state) {
    for (const auto& [zone, interfaces] : state.active_zone_interfaces)
        for (const auto& interface : interfaces)
            return {interface, zone};
    return {"unavailable", state.default_zone.empty() ? "unavailable" : state.default_zone};
}

std::string primary_gap(const DashboardSnapshot& snapshot) {
    if (snapshot.coverage_gaps.empty())
        return "none";
    const auto meaningful = std::find_if(snapshot.coverage_gaps.begin(), snapshot.coverage_gaps.end(),
                                         [](const DashboardFinding& gap) {
                                             return gap.id.find("NetworkManager") != std::string::npos ||
                                                    gap.id.find("kernel") != std::string::npos ||
                                                    gap.id.find("VPN") != std::string::npos;
                                         });
    return (meaningful == snapshot.coverage_gaps.end() ? snapshot.coverage_gaps.front() : *meaningful)
        .summary;
}
} // namespace

std::string PostureRenderer::items_or_none(const std::vector<std::string> &items) {
    std::string result;
    for (const auto &item : items)
        result += (result.empty() ? "" : ", ") + item;
    return result.empty() ? "none" : result;
}
void PostureRenderer::show_status(const FirewallState &state) const {
    ui_.section("Firewall posture");
    ui_.key_value("Firewalld", !observation_available(state.service_state)
                                   ? ui_.warning_badge("UNKNOWN")
                               : state.active ? ui_.success_badge("ACTIVE")
                                              : ui_.danger_badge("INACTIVE"));
    ui_.key_value("Boot service", !observation_available(state.service_enablement)
                                      ? ui_.warning_badge("UNKNOWN")
                                  : state.enabled ? ui_.success_badge("ENABLED")
                                                  : ui_.warning_badge("NOT ENABLED"));
    ui_.key_value("Panic mode", !observation_available(state.panic_state)
                                    ? ui_.warning_badge("UNKNOWN")
                                : state.panic ? ui_.danger_badge("ACTIVE")
                                              : ui_.success_badge("OFF"));
    ui_.key_value("Assessment mode", state.operating_mode == OperatingMode::HostileNetwork
                                         ? ui_.warning_badge("HOSTILE NETWORK")
                                         : ui_.neutral_badge("NORMAL"));
    ui_.key_value("Permanent config",
                  observation_available(state.permanent_config)
                      ? (state.permanent_config_valid ? ui_.success_badge("VALID")
                                                      : ui_.danger_badge("INVALID"))
                      : ui_.warning_badge("UNKNOWN"));
    ui_.key_value("Default zone", !observation_available(state.default_zone_status)
                                      ? ui_.warning("unknown")
                                  : state.default_zone.empty() ? ui_.warning("missing")
                                                               : ui_.accent(state.default_zone));
    ui_.key_value("Denied-packet logging",
                  !observation_available(state.denied_logging_status) ? ui_.warning("unknown")
                  : state.log_denied == "off"                         ? ui_.muted("off")
                  : state.log_denied.empty() ? ui_.warning("unknown")
                                             : ui_.warning(state.log_denied));
    for (const auto &error : state.errors)
        ui_.key_value("Notice", ui_.warning(error));
}
void PostureRenderer::show_dashboard_home(const DashboardState& dashboard) const {
    const auto& state = dashboard.firewall;
    const auto exposure = active_exposure_counts(state);
    const auto interface_name = physical_interface_and_zone(state).first;
    const auto risk = dashboard.risk == DashboardRisk::Blocked
                          ? ui_.danger_badge(std::string{to_string(dashboard.risk)})
                      : dashboard.risk == DashboardRisk::Review
                          ? ui_.warning_badge(std::string{to_string(dashboard.risk)})
                          : ui_.success_badge(std::string{to_string(dashboard.risk)});
    const auto tunnel = !state.vpn.interface_scan_available ? ui_.warning("tunnel scan unavailable")
                      : state.vpn.active_tunnel_interfaces.empty() ? ui_.muted("no tunnel detected")
                      : ui_.success(items_or_none(state.vpn.active_tunnel_interfaces) + " detected");
    std::cout << "  " << dashboard.hostname << " • "
              << (state.operating_mode == OperatingMode::HostileNetwork ? "HOSTILE" : "NORMAL")
              << " • snapshot " << format_dashboard_age(dashboard) << " • evidence "
              << (dashboard.overall_evidence == ObservationStatus::Available ? "complete"
                  : dashboard.overall_evidence == ObservationStatus::Partial ? "partial" : "unavailable")
              << '\n';
    std::cout << "  Risk       " << risk << '\n';
    std::cout << "  Firewall   "
              << (!observation_available(state.service_state) ? ui_.warning("UNKNOWN")
                  : state.active ? ui_.success("ACTIVE") + " • " +
                                       std::to_string(exposure.ports) + " inbound rule(s) • forwarding " +
                                       (exposure.forwarding ? ui_.warning("ON") : ui_.success("OFF"))
                                 : ui_.danger("INACTIVE")) << '\n';
    std::cout << "  Network    " << interface_name << " • " << tunnel
              << " • route " << ui_.warning("UNVERIFIED") << '\n';
    std::cout << "  Alerts     " << std::to_string(dashboard.review_items.size()) << " review item(s) • "
              << std::to_string(dashboard.coverage_gaps.size()) << " coverage gap(s)\n";
    const auto home_action = dashboard.recommendations.empty()
                                 ? ui_.success("No modeled defensive action")
                                 : dashboard.recommendations.front().category == FindingCategory::Exposure
                                     ? ui_.warning("Review firewall exposure; open Firewall")
                                     : dashboard.recommendations.front().category == FindingCategory::Listener
                                         ? ui_.warning("Review host listeners; open Firewall")
                                         : dashboard.recommendations.front().category == FindingCategory::EvidenceGap
                                             ? ui_.warning("Review evidence gap; open Evidence")
                                             : dashboard.recommendations.front().summary;
    std::cout << "  Action     " << home_action << '\n';
}
void PostureRenderer::show_dashboard_snapshot(const DashboardState &dashboard) const {
    const auto& state = dashboard.firewall;
    const auto exposure = active_exposure_counts(state);
    const bool policy_details_available = applicable_zone_details_available(state);
    const auto [interface_name, zone_name] = physical_interface_and_zone(state);
    ui_.key_value("Host", dashboard.hostname + " • snapshot " + std::to_string(dashboard.snapshot_id));
    ui_.key_value("Snapshot", format_dashboard_age(dashboard) + " • " +
                                format_dashboard_local_time(dashboard.collected_at) + " • " +
                                format_dashboard_timestamp(dashboard.collected_at));
    ui_.section("Operational status");
    const auto risk = dashboard.risk == DashboardRisk::Blocked
                          ? ui_.danger_badge(std::string{to_string(dashboard.risk)})
                      : dashboard.risk == DashboardRisk::Review
                          ? ui_.warning_badge(std::string{to_string(dashboard.risk)})
                          : ui_.success_badge(std::string{to_string(dashboard.risk)});
    const auto defcon = dashboard.defcon_readiness == DefconReadiness::NotReady
                            ? ui_.danger_badge(std::string{to_string(dashboard.defcon_readiness)})
                        : dashboard.defcon_readiness == DefconReadiness::Ready
                            ? ui_.success_badge(std::string{to_string(dashboard.defcon_readiness)})
                            : ui_.warning_badge(std::string{to_string(dashboard.defcon_readiness)});
    const auto boot = !observation_available(state.service_enablement) ? ui_.warning("unknown")
                      : state.enabled ? ui_.success("enabled") : ui_.warning("not enabled");
    const auto config = !observation_available(state.permanent_config) ? ui_.warning("unknown")
                        : state.permanent_config_valid ? ui_.success("valid") : ui_.warning("review");
    ui_.key_value("DEF CON readiness", defcon + " • " +
                                      (state.operating_mode == OperatingMode::HostileNetwork
                                           ? ui_.warning("HOSTILE criteria")
                                           : ui_.neutral_badge("NORMAL criteria")));
    ui_.key_value("Current posture", risk + " • " +
                                      std::to_string(dashboard.review_items.size()) + " direct review item(s)");
    ui_.key_value("Firewalld", !observation_available(state.service_state)
                                   ? ui_.warning_badge("UNKNOWN")
                               : state.active ? ui_.success_badge("ACTIVE") + ui_.muted(" • current host policy enforced • boot: ") +
                                                    boot + ui_.muted(" • config: ") + config
                                              : ui_.danger_badge("INACTIVE"));
    ui_.key_value("FFC control", ui_.neutral_badge("READ-ONLY") +
                                   ui_.muted(" • no managed defense profile"));
    ui_.key_value("Isolation", ui_.muted("NOT AVAILABLE • emergency actions are not installed"));
    ui_.key_value("Evidence", (dashboard.overall_evidence == ObservationStatus::Available
                                     ? ui_.success("complete")
                                 : dashboard.overall_evidence == ObservationStatus::Partial
                                     ? ui_.warning("partial")
                                     : ui_.danger("unavailable")) +
                                  " • " + std::to_string(dashboard.coverage_gaps.size()) + " coverage gap(s)");
    ui_.section("Network path");
    ui_.key_value("Physical interface", interface_name);
    ui_.key_value("Firewalld zone", zone_name);
    ui_.key_value("NetworkManager profile",
                  state.network_manager.available
                      ? ui_.muted("not collected by this snapshot")
                      : ui_.warning("device inventory unavailable: " + state.network_manager.diagnostic));
    ui_.key_value("Tunnel interface", !state.vpn.interface_scan_available ? ui_.warning("scan unavailable")
                               : state.vpn.active_tunnel_interfaces.empty() ? ui_.muted("none detected")
                               : ui_.success(items_or_none(state.vpn.active_tunnel_interfaces) + " detected"));
    ui_.key_value("VPN route", ui_.warning("UNVERIFIED"));
    ui_.key_value("DNS / kill switch", ui_.warning("UNVERIFIED"));
    ui_.section("Exposure requiring review");
    if (!policy_details_available) {
        ui_.key_value("Active firewall rules", ui_.warning("applicable policy evidence unavailable"));
    } else {
        ui_.key_value("Active firewall rules",
                      std::to_string(exposure.ports) + " port rules • " +
                          std::to_string(exposure.protocols) + " protocol rules • " +
                          std::to_string(exposure.rich_rules) + " rich rules");
        ui_.key_value("Routing policy", exposure.forwarding
                                           ? ui_.warning_badge("INTRA-ZONE FORWARDING ON")
                                           : ui_.success("intra-zone forwarding off"));
    }
    if (!state.sockets.available)
        ui_.key_value("Host listeners", ui_.warning("TCP/UDP listener scan unavailable"));
    else {
        const auto listeners = summarize_listener_exposure(state.sockets);
        ui_.key_value("Host listeners", std::to_string(listeners.logical_network_services) +
                                            " TCP/UDP listeners • " +
                                            std::to_string(listeners.network_reachable_bindings) +
                                            " reachable bindings");
        ui_.key_value("Multicast listeners", std::to_string(listeners.multicast_only_bindings));
    }
    const std::string denied = !state.security_signals.kernel_journal_available ? ui_.warning("UNAVAILABLE")
        : state.security_signals.kernel_drop_or_reject_events == 0
            ? ui_.success("no denied events")
            : ui_.warning(std::to_string(state.security_signals.kernel_drop_or_reject_events) +
                          " denied events");
    ui_.key_value("Denied-packet evidence", denied);
    ui_.key_value("Firewalld service events",
                  !state.security_signals.firewalld_journal_available
                      ? ui_.warning("UNAVAILABLE")
                      : std::to_string(state.security_signals.firewalld_service_events) + " in the last 24h");
    ui_.section("Recommended action");
    if (dashboard.recommendations.empty())
        std::cout << "  " << ui_.success("No modeled defensive action is currently recommended.") << '\n';
    else
        std::cout << "  " << sanitize_terminal_text(dashboard.recommendations.front().summary) << "  "
                  << ui_.muted("[Open: " + std::string{to_string(dashboard.recommendations.front().destination)} + "]") << '\n';
    ui_.section("Coverage gap");
    std::cout << "  " << sanitize_terminal_text(primary_gap(dashboard)) << '\n';
}
void PostureRenderer::show_overview(const FirewallState &state) const {
    ui_.section("Active interface assignments");
    bool found = false;
    if (!observation_available(state.active_zones_status))
        std::cout << "  " << ui_.warning("Active-zone query is unavailable.") << '\n';
    for (const auto &[zone, interfaces] : state.active_zone_interfaces)
        for (const auto &interface : interfaces) {
            std::cout << "  " << ui_.accent(interface) << "  " << ui_.muted("→") << "  " << ui_.accent(zone)
                      << (zone == state.default_zone ? ui_.muted("  default") : "") << '\n';
            found = true;
        }
    for (const auto &[zone, sources] : state.active_zone_sources)
        for (const auto &source : sources) {
            std::cout << "  " << ui_.accent(source) << "  " << ui_.muted("→") << "  " << ui_.accent(zone)
                      << ui_.muted("  source")
                      << (zone == state.default_zone ? ui_.muted("  default") : "") << '\n';
            found = true;
        }
    if (!found)
        std::cout << "  "
                  << (!observation_available(state.active_zones_status)
                          ? ui_.warning("Active-zone assignments are unavailable.")
                          : ui_.muted("No active zone assignments reported."))
                  << '\n';
    ui_.section("NetworkManager device state");
    if (!state.network_manager.available)
        std::cout << "  " << ui_.warning("NetworkManager status is unavailable.") << '\n';
    else if (state.network_manager.devices.empty())
        std::cout << "  " << ui_.muted("No NetworkManager devices reported.") << '\n';
    else
        for (const auto &device : state.network_manager.devices)
            std::cout << "  " << ui_.accent(device.interface_name) << "  " << ui_.muted(device.type)
                      << "  "
                      << (device.state.rfind("connected", 0) == 0 ? ui_.success(device.state)
                                                                  : ui_.muted(device.state))
                      << '\n';
    ui_.section("VPN awareness");
    ui_.key_value("NordVPN client", state.vpn.nordvpn_installed ? ui_.success("installed")
                                                                : ui_.muted("not detected"));
    if (!state.vpn.interface_scan_available)
        ui_.key_value("Tunnel scan", ui_.warning("unavailable"));
    else
        ui_.key_value("Active tunnel interfaces",
                      state.vpn.active_tunnel_interfaces.empty()
                          ? ui_.muted("none")
                          : items_or_none(state.vpn.active_tunnel_interfaces));
    size_t loopback_listeners = 0;
    for (const auto &listener : state.sockets.listeners)
        if (listener.loopback_only)
            ++loopback_listeners;
    ui_.section("Local listener summary");
    if (!state.sockets.available)
        ui_.key_value("Socket scan", ui_.warning("unavailable"));
    else {
        const auto exposure = summarize_listener_exposure(state.sockets);
        ui_.key_value("Network-reachable services",
                      exposure.logical_network_services == 0
                          ? ui_.success("NONE")
                          : ui_.warning(std::to_string(exposure.logical_network_services) +
                                        " logical service(s)"));
        ui_.key_value("Network-reachable bindings",
                      std::to_string(exposure.network_reachable_bindings));
        ui_.key_value("Multicast-only bindings", std::to_string(exposure.multicast_only_bindings));
        ui_.key_value("Loopback-only listeners", std::to_string(loopback_listeners));
    }
    ui_.section("Recent security signals (24h)");
    if (state.security_signals.kernel_journal_status == JournalQueryStatus::Partial)
        ui_.key_value("Kernel drop/reject log entries",
                      ui_.warning("at least " +
                                  std::to_string(state.security_signals.kernel_drop_or_reject_events) +
                                  " (bounded view)"));
    else if (!state.security_signals.kernel_journal_available)
        ui_.key_value("Kernel drop/reject log", ui_.warning("unavailable"));
    else
        ui_.key_value(
            "Kernel drop/reject log entries",
            state.security_signals.kernel_drop_or_reject_events == 0
                ? ui_.success("none")
                : ui_.warning(std::to_string(state.security_signals.kernel_drop_or_reject_events)));
    if (state.security_signals.firewalld_journal_status == JournalQueryStatus::Partial)
        ui_.key_value("firewalld service journal entries",
                      ui_.warning("at least " +
                                  std::to_string(state.security_signals.firewalld_service_events) +
                                  " (bounded view)"));
    else if (!state.security_signals.firewalld_journal_available)
        ui_.key_value("firewalld service journal", ui_.warning("unavailable"));
    else
        ui_.key_value("firewalld service journal entries",
                      std::to_string(state.security_signals.firewalld_service_events));
    const auto exposure = active_exposure_counts(state);
    const bool policy_details_available = applicable_zone_details_available(state);
    ui_.section("Exposure summary");
    ui_.key_value("Allowed services",
                  !policy_details_available ? ui_.warning("UNKNOWN")
                  : exposure.services == 0
                      ? ui_.success("NONE")
                      : ui_.warning(std::to_string(exposure.services) + " configured"));
    ui_.key_value("Explicit ports",
                  !policy_details_available ? ui_.warning("UNKNOWN")
                  : exposure.ports == 0
                      ? ui_.success("NONE")
                      : ui_.warning(std::to_string(exposure.ports) + " configured"));
    ui_.key_value("Allowed protocols",
                  !policy_details_available ? ui_.warning("UNKNOWN")
                  : exposure.protocols == 0
                      ? ui_.success("NONE")
                      : ui_.warning(std::to_string(exposure.protocols) + " configured"));
    ui_.key_value("Source-port rules",
                  !policy_details_available ? ui_.warning("UNKNOWN")
                  : exposure.source_ports == 0
                      ? ui_.success("NONE")
                      : ui_.warning(std::to_string(exposure.source_ports) + " configured"));
    ui_.key_value("Rich rules", !policy_details_available ? ui_.warning("UNKNOWN")
                                                          : std::to_string(exposure.rich_rules));
    ui_.key_value("Forward ports",
                  !policy_details_available ? ui_.warning("UNKNOWN")
                  : exposure.forward_ports == 0
                      ? ui_.success("NONE")
                      : ui_.warning(std::to_string(exposure.forward_ports) + " configured"));
    ui_.key_value("Intra-zone forwarding", !policy_details_available ? ui_.warning("UNKNOWN")
                                           : exposure.forwarding     ? ui_.warning("ENABLED")
                                                                     : ui_.success("DISABLED"));
    ui_.key_value("Masquerading", !policy_details_available ? ui_.warning("UNKNOWN")
                                  : exposure.masquerade     ? ui_.warning("ENABLED")
                                                            : ui_.success("DISABLED"));
    ui_.key_value("Active policies",
                  !observation_available(state.active_policies_status) ? ui_.warning("UNKNOWN")
                  : state.active_policies.empty() ? ui_.muted("none")
                                                  : items_or_none(state.active_policies));
}
void PostureRenderer::show_listeners(const FirewallState &state) const {
    ui_.section("Network-visible listening sockets");
    if (!state.sockets.available) {
        std::cout << "  " << ui_.warning("Socket scan is unavailable.") << '\n';
        return;
    }
    bool found = false;
    for (const auto &listener : state.sockets.listeners)
        if (!listener.loopback_only) {
            const auto intel = identify_endpoint(listener.endpoint, listener.protocol);
            const auto owner =
                listener.process_name.empty() ? "" : " • owner: " + listener.process_name;
            const auto scope = listener.multicast_only ? " • multicast-only" : "";
            std::cout << "  " << ui_.warning(listener.protocol) << "  " << sanitize_terminal_text(listener.endpoint)
                      << ui_.muted(" — " + port_intel_label(intel) + owner + scope) << '\n';
            found = true;
        }
    if (!found)
        std::cout << "  " << ui_.success("No non-loopback listening sockets detected.") << '\n';
}
void PostureRenderer::show_threat_assessment(const FirewallState &state) const {
    const auto assessment = assess_threat_evidence(state);
    ui_.heading("Threat evidence assessment",
                "Read-only triage — candidate alerts are not confirmed incidents");
    for (const auto &finding : assessment.findings) {
        const auto kind = to_string(finding.kind);
        const auto badge = finding.kind == ThreatFindingKind::CoverageGap ||
                                   finding.kind == ThreatFindingKind::CandidateAlert
                               ? ui_.warning_badge(kind)
                           : finding.kind == ThreatFindingKind::Exposure ||
                                   finding.kind == ThreatFindingKind::ScopeLimit
                               ? ui_.neutral_badge(kind)
                               : ui_.success_badge(kind);
        std::cout << "  " << badge << "  " << sanitize_terminal_text(finding.title) << '\n';
        std::cout << "      " << ui_.muted(finding.detail) << '\n';
        std::cout << "      "
                  << ui_.muted("False-positive / false-negative context: " +
                               finding.false_positive_context)
                  << '\n';
        std::cout << "      " << ui_.accent("Validate: ") << sanitize_terminal_text(finding.validation_step) << '\n';
    }
    ui_.section("Verdict guardrails");
    for (const auto &rule : assessment.verdict_rules)
        std::cout << "  " << ui_.muted("• ") << sanitize_terminal_text(rule) << '\n';
}
void PostureRenderer::show_zones(const FirewallState &state, const std::string &title,
                                 ZoneView view, ZoneScope scope) const {
    ui_.section(title);
    if (!observation_available(state.runtime_zones_status)) {
        std::cout << "  " << ui_.warning("Runtime zone policy is unavailable.") << '\n';
        return;
    }
    bool displayed = false;
    for (const auto &[name, zone] : state.runtime_zones) {
        const bool applicable = is_zone_applicable(state, name);
        const bool default_zone = name == state.default_zone;
        if (scope == ZoneScope::ActiveAndDefault && !applicable && !default_zone)
            continue;

        displayed = true;
        const std::string markers =
            std::string(applicable ? "  (applicable)" : "") +
            (default_zone ? "  (default)" : "");
        std::cout << "  " << ui_.accent(name) << ui_.muted(markers) << '\n';
        if (view == ZoneView::All)
            ui_.key_value("target", zone.target.empty()       ? "unknown"
                                    : zone.target == "ACCEPT" ? ui_.danger(zone.target)
                                                              : zone.target);
        if (view == ZoneView::All || view == ZoneView::Interfaces) {
            ui_.key_value("interfaces", items_or_none(zone.interfaces));
            ui_.key_value("sources", items_or_none(zone.sources));
        }
        if (view == ZoneView::All || view == ZoneView::Services)
            ui_.key_value("services", items_or_none(zone.services));
        if (view == ZoneView::All || view == ZoneView::Ports) {
            ui_.key_value("ports", annotated_port_list(zone.ports));
            ui_.key_value("protocols", items_or_none(zone.protocols));
            ui_.key_value("source ports", items_or_none(zone.source_ports));
        }
        if (view == ZoneView::All || view == ZoneView::RichRules)
            ui_.key_value("rich rules", std::to_string(zone.rich_rules.size()));
        if (view == ZoneView::All || view == ZoneView::Routing) {
            ui_.key_value("forward ports", items_or_none(zone.forward_ports));
            ui_.key_value("intra-zone forwarding",
                          zone.forward ? ui_.warning("enabled") : ui_.success("disabled"));
            ui_.key_value("masquerade",
                          zone.masquerade ? ui_.warning("enabled") : ui_.success("disabled"));
        }
        if (view == ZoneView::Drift) {
            const auto permanent = state.permanent_zones.find(name);
            const bool permanent_available = observation_available(state.permanent_zones_status);
            const bool same = permanent_available && permanent != state.permanent_zones.end() &&
                              zone_policies_equal(zone, permanent->second);
            ui_.key_value("policy configuration", !permanent_available ? ui_.warning("unknown")
                                                  : same ? ui_.success("matches permanent")
                                                         : ui_.warning("differs from permanent"));
            if (permanent != state.permanent_zones.end() &&
                zone.interfaces != permanent->second.interfaces)
                ui_.key_value("interface binding",
                              ui_.muted("runtime assignment differs; commonly managed "
                                        "by NetworkManager"));
        }
        std::cout << '\n';
    }
    if (!displayed)
        std::cout << "  " << ui_.warning("No active or default zone policy was reported.") << '\n';
}
void PostureRenderer::show_readiness(const FirewallState &state) const {
    ui_.heading("DEF CON Firewall Readiness",
                "Read-only assessment — review warnings before connecting to "
                "hostile networks");
    for (const auto &check : assess_readiness(state)) {
        const std::string result = check.level == CheckLevel::Pass   ? ui_.success_badge("PASS")
                                   : check.level == CheckLevel::Warn ? ui_.warning_badge("WARN")
                                   : check.level == CheckLevel::Fail ? ui_.danger_badge("FAIL")
                                                                     : ui_.neutral_badge("INFO");
        std::cout << "  " << result << "  " << check.label
                  << (check.detail.empty() ? "" : ui_.muted(" — " + check.detail)) << '\n';
    }
}
} // namespace ffc
