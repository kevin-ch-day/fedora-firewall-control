#include "ffc/posture_renderer.hpp"

#include "ffc/port_intelligence.hpp"
#include "ffc/readiness.hpp"
#include "ffc/threat_assessment.hpp"

#include <iostream>

namespace ffc {
namespace {
std::string annotated_port_list(const std::vector<std::string>& ports) {
    if (ports.empty()) return "none";
    std::string result;
    for (const auto& port : ports) result += (result.empty() ? "" : ", ") + port + " (" + port_intel_label(identify_port_spec(port)) + ")";
    return result;
}
} // namespace

std::string PostureRenderer::items_or_none(const std::vector<std::string>& items) { std::string result; for (const auto& item : items) result += (result.empty() ? "" : ", ") + item; return result.empty() ? "none" : result; }
void PostureRenderer::show_status(const FirewallState& state) const {
    ui_.section("Firewall posture");
    ui_.key_value("Firewalld", state.active ? ui_.success_badge("ACTIVE") : ui_.danger_badge("INACTIVE")); ui_.key_value("Boot service", state.enabled ? ui_.success_badge("ENABLED") : ui_.warning_badge("NOT ENABLED")); ui_.key_value("Panic mode", state.panic ? ui_.danger_badge("ACTIVE") : ui_.success_badge("OFF"));
    ui_.key_value("Assessment mode", state.operating_mode == OperatingMode::HostileNetwork ? ui_.warning_badge("HOSTILE NETWORK") : ui_.neutral_badge("NORMAL")); ui_.key_value("Permanent config", state.permanent_config_checked ? (state.permanent_config_valid ? ui_.success_badge("VALID") : ui_.danger_badge("INVALID")) : ui_.warning_badge("NOT CHECKED"));
    ui_.key_value("Default zone", state.default_zone.empty() ? ui_.warning("unknown") : ui_.accent(state.default_zone)); ui_.key_value("Denied-packet logging", state.log_denied.empty() ? ui_.muted("unknown") : state.log_denied == "off" ? ui_.muted("off") : ui_.warning(state.log_denied)); for (const auto& error : state.errors) ui_.key_value("Notice", ui_.warning(error));
}
void PostureRenderer::show_overview(const FirewallState& state) const {
    ui_.section("Active interface assignments"); bool found = false;
    for (const auto& [zone, interfaces] : state.active_zone_interfaces) for (const auto& interface : interfaces) { std::cout << "  " << ui_.accent(interface) << "  " << ui_.muted("→") << "  " << zone << (zone == state.default_zone ? ui_.muted("  default") : "") << '\n'; found = true; }
    if (!found) std::cout << "  " << ui_.muted("No active zone assignments reported.") << '\n';
    ui_.section("NetworkManager device state");
    if (!state.network_manager.available) std::cout << "  " << ui_.warning("NetworkManager status is unavailable.") << '\n'; else if (state.network_manager.devices.empty()) std::cout << "  " << ui_.muted("No NetworkManager devices reported.") << '\n'; else for (const auto& device : state.network_manager.devices) std::cout << "  " << ui_.accent(device.interface_name) << "  " << ui_.muted(device.type) << "  " << (device.state.rfind("connected", 0) == 0 ? ui_.success(device.state) : ui_.muted(device.state)) << '\n';
    ui_.section("VPN awareness"); ui_.key_value("NordVPN client", state.vpn.nordvpn_installed ? ui_.success("installed") : ui_.muted("not detected")); if (!state.vpn.interface_scan_available) ui_.key_value("Tunnel scan", ui_.warning("unavailable")); else ui_.key_value("Active tunnel interfaces", state.vpn.active_tunnel_interfaces.empty() ? ui_.muted("none") : items_or_none(state.vpn.active_tunnel_interfaces));
    size_t loopback_listeners = 0; for (const auto& listener : state.sockets.listeners) if (listener.loopback_only) ++loopback_listeners;
    ui_.section("Local listener summary"); if (!state.sockets.available) ui_.key_value("Socket scan", ui_.warning("unavailable")); else { const auto exposure = summarize_listener_exposure(state.sockets); ui_.key_value("Network-reachable services", exposure.logical_network_services == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(exposure.logical_network_services) + " logical service(s)")); ui_.key_value("Network-reachable bindings", std::to_string(exposure.network_reachable_bindings)); ui_.key_value("Multicast-only bindings", std::to_string(exposure.multicast_only_bindings)); ui_.key_value("Loopback-only listeners", std::to_string(loopback_listeners)); }
    ui_.section("Recent security signals (24h)"); if (!state.security_signals.kernel_journal_available) ui_.key_value("Kernel drop/reject log", ui_.warning("unavailable")); else ui_.key_value("Kernel drop/reject log entries", state.security_signals.kernel_drop_or_reject_events == 0 ? ui_.success("none") : ui_.warning(std::to_string(state.security_signals.kernel_drop_or_reject_events))); if (!state.security_signals.firewalld_journal_available) ui_.key_value("firewalld service journal", ui_.warning("unavailable")); else ui_.key_value("firewalld service journal entries", std::to_string(state.security_signals.firewalld_service_events));
    size_t services = 0, ports = 0, rich_rules = 0, forward_ports = 0; bool forwarding = false, masquerade = false; for (const auto& [zone_name, zone] : state.runtime_zones) { if (state.active_zone_interfaces.contains(zone_name)) { services += zone.services.size(); ports += zone.ports.size(); rich_rules += zone.rich_rules.size(); forward_ports += zone.forward_ports.size(); forwarding = forwarding || zone.forward; masquerade = masquerade || zone.masquerade; } }
    ui_.section("Exposure summary"); ui_.key_value("Allowed services", services == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(services) + " configured")); ui_.key_value("Explicit ports", ports == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(ports) + " configured")); ui_.key_value("Rich rules", std::to_string(rich_rules)); ui_.key_value("Forward ports", forward_ports == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(forward_ports) + " configured")); ui_.key_value("Intra-zone forwarding", forwarding ? ui_.warning("ENABLED") : ui_.success("DISABLED")); ui_.key_value("Masquerading", masquerade ? ui_.warning("ENABLED") : ui_.success("DISABLED")); ui_.key_value("Active policies", state.active_policies.empty() ? ui_.muted("none") : items_or_none(state.active_policies));
}
void PostureRenderer::show_listeners(const FirewallState& state) const { ui_.section("Network-visible listening sockets"); if (!state.sockets.available) { std::cout << "  " << ui_.warning("Socket scan is unavailable.") << '\n'; return; } bool found = false; for (const auto& listener : state.sockets.listeners) if (!listener.loopback_only) { const auto intel = identify_endpoint(listener.endpoint, listener.protocol); const auto owner = listener.process_name.empty() ? "" : " • owner: " + listener.process_name; const auto scope = listener.multicast_only ? " • multicast-only" : ""; std::cout << "  " << ui_.warning(listener.protocol) << "  " << listener.endpoint << ui_.muted(" — " + port_intel_label(intel) + owner + scope) << '\n'; found = true; } if (!found) std::cout << "  " << ui_.success("No non-loopback listening sockets detected.") << '\n'; }
void PostureRenderer::show_threat_assessment(const FirewallState& state) const {
    const auto assessment = assess_threat_evidence(state);
    ui_.heading("Threat evidence assessment", "Read-only triage — candidate alerts are not confirmed incidents");
    for (const auto& finding : assessment.findings) {
        const auto kind = to_string(finding.kind);
        const auto badge = finding.kind == ThreatFindingKind::CoverageGap || finding.kind == ThreatFindingKind::CandidateAlert ? ui_.warning_badge(kind) : finding.kind == ThreatFindingKind::Exposure || finding.kind == ThreatFindingKind::ScopeLimit ? ui_.neutral_badge(kind) : ui_.success_badge(kind);
        std::cout << "  " << badge << "  " << finding.title << '\n';
        std::cout << "      " << ui_.muted(finding.detail) << '\n';
        std::cout << "      " << ui_.muted("False-positive / false-negative context: " + finding.false_positive_context) << '\n';
        std::cout << "      " << ui_.accent("Validate: ") << finding.validation_step << '\n';
    }
    ui_.section("Verdict guardrails");
    for (const auto& rule : assessment.verdict_rules) std::cout << "  " << ui_.muted("• ") << rule << '\n';
}
void PostureRenderer::show_zones(const FirewallState& state, const std::string& title, ZoneView view) const { ui_.section(title); for (const auto& [name, zone] : state.runtime_zones) { std::cout << "  " << ui_.accent(name) << (name == state.default_zone ? ui_.muted("  (default)") : "") << '\n'; if (view == ZoneView::All) ui_.key_value("target", zone.target.empty() ? "unknown" : zone.target == "ACCEPT" ? ui_.danger(zone.target) : zone.target); if (view == ZoneView::All || view == ZoneView::Interfaces) { ui_.key_value("interfaces", items_or_none(zone.interfaces)); ui_.key_value("sources", items_or_none(zone.sources)); } if (view == ZoneView::All || view == ZoneView::Services) ui_.key_value("services", items_or_none(zone.services)); if (view == ZoneView::All || view == ZoneView::Ports) ui_.key_value("ports", annotated_port_list(zone.ports)); if (view == ZoneView::All || view == ZoneView::RichRules) ui_.key_value("rich rules", std::to_string(zone.rich_rules.size())); if (view == ZoneView::All || view == ZoneView::Routing) { ui_.key_value("forward ports", items_or_none(zone.forward_ports)); ui_.key_value("intra-zone forwarding", zone.forward ? ui_.warning("enabled") : ui_.success("disabled")); ui_.key_value("masquerade", zone.masquerade ? ui_.warning("enabled") : ui_.success("disabled")); } if (view == ZoneView::Drift) { const auto permanent = state.permanent_zones.find(name); const bool same = permanent != state.permanent_zones.end() && zone_policies_equal(zone, permanent->second); ui_.key_value("policy configuration", same ? ui_.success("matches permanent") : ui_.warning("differs from permanent")); if (permanent != state.permanent_zones.end() && zone.interfaces != permanent->second.interfaces) ui_.key_value("interface binding", ui_.muted("runtime assignment differs; commonly managed by NetworkManager")); } std::cout << '\n'; } }
void PostureRenderer::show_readiness(const FirewallState& state) const { ui_.heading("DEF CON Firewall Readiness", "Read-only assessment — review warnings before connecting to hostile networks"); for (const auto& check : assess_readiness(state)) { const std::string result = check.level == CheckLevel::Pass ? ui_.success_badge("PASS") : check.level == CheckLevel::Warn ? ui_.warning_badge("WARN") : check.level == CheckLevel::Fail ? ui_.danger_badge("FAIL") : ui_.neutral_badge("INFO"); std::cout << "  " << result << "  " << check.label << (check.detail.empty() ? "" : ui_.muted(" — " + check.detail)) << '\n'; } }
} // namespace ffc
