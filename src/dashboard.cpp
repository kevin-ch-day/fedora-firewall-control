#include "ffc/dashboard.hpp"

#include "ffc/readiness.hpp"

#include <algorithm>
#include <iostream>

namespace ffc {
std::string Dashboard::items_or_none(const std::vector<std::string>& items) {
    if (items.empty()) return "none";
    std::string result;
    for (const auto& item : items) result += (result.empty() ? "" : ", ") + item;
    return result;
}

void Dashboard::show_status(const FirewallState& state) const {
    ui_.section("Firewall posture");
    ui_.key_value("Firewalld", state.active ? ui_.success_badge("ACTIVE") : ui_.danger_badge("INACTIVE"));
    ui_.key_value("Boot service", state.enabled ? ui_.success_badge("ENABLED") : ui_.warning_badge("NOT ENABLED"));
    ui_.key_value("Panic mode", state.panic ? ui_.danger_badge("ACTIVE") : ui_.success_badge("OFF"));
    ui_.key_value("Assessment mode", state.operating_mode == OperatingMode::HostileNetwork ? ui_.warning_badge("HOSTILE NETWORK") : ui_.neutral_badge("NORMAL"));
    ui_.key_value("Permanent config", state.permanent_config_checked ? (state.permanent_config_valid ? ui_.success_badge("VALID") : ui_.danger_badge("INVALID")) : ui_.warning_badge("NOT CHECKED"));
    ui_.key_value("Default zone", state.default_zone.empty() ? ui_.warning("unknown") : ui_.accent(state.default_zone));
    ui_.key_value("Denied-packet logging", state.log_denied.empty() ? ui_.muted("unknown") : state.log_denied == "off" ? ui_.muted("off") : ui_.warning(state.log_denied));
    for (const auto& error : state.errors) ui_.key_value("Notice", ui_.warning(error));
}

void Dashboard::show_overview(const FirewallState& state) const {
    ui_.section("Active interface assignments");
    bool found = false;
    for (const auto& [zone, interfaces] : state.active_zone_interfaces) for (const auto& interface : interfaces) {
        std::cout << "  " << ui_.accent(interface) << "  " << ui_.muted("→") << "  " << zone
                  << (zone == state.default_zone ? ui_.muted("  default") : "") << '\n';
        found = true;
    }
    if (!found) std::cout << "  " << ui_.muted("No active zone assignments reported.") << '\n';

    ui_.section("NetworkManager device state");
    if (!state.network_manager.available) {
        std::cout << "  " << ui_.warning("NetworkManager status is unavailable.") << '\n';
    } else if (state.network_manager.devices.empty()) {
        std::cout << "  " << ui_.muted("No NetworkManager devices reported.") << '\n';
    } else {
        for (const auto& device : state.network_manager.devices) {
            std::cout << "  " << ui_.accent(device.interface_name) << "  " << ui_.muted(device.type) << "  "
                      << (device.state.rfind("connected", 0) == 0 ? ui_.success(device.state) : ui_.muted(device.state)) << '\n';
        }
    }

    ui_.section("VPN awareness");
    ui_.key_value("NordVPN client", state.vpn.nordvpn_installed ? ui_.success("installed") : ui_.muted("not detected"));
    if (!state.vpn.interface_scan_available) ui_.key_value("Tunnel scan", ui_.warning("unavailable"));
    else ui_.key_value("Active tunnel interfaces", state.vpn.active_tunnel_interfaces.empty() ? ui_.muted("none") : items_or_none(state.vpn.active_tunnel_interfaces));

    size_t network_listeners = 0, loopback_listeners = 0;
    for (const auto& listener : state.sockets.listeners) listener.loopback_only ? ++loopback_listeners : ++network_listeners;
    ui_.section("Local listener summary");
    if (!state.sockets.available) ui_.key_value("Socket scan", ui_.warning("unavailable"));
    else {
        ui_.key_value("Network-reachable listeners", network_listeners == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(network_listeners)));
        ui_.key_value("Loopback-only listeners", std::to_string(loopback_listeners));
    }

    ui_.section("Recent security signals (24h)");
    if (!state.security_signals.kernel_journal_available) ui_.key_value("Kernel drop/reject log", ui_.warning("unavailable"));
    else ui_.key_value("Kernel drop/reject log entries", state.security_signals.kernel_drop_or_reject_events == 0 ? ui_.success("none") : ui_.warning(std::to_string(state.security_signals.kernel_drop_or_reject_events)));
    if (!state.security_signals.firewalld_journal_available) ui_.key_value("firewalld service journal", ui_.warning("unavailable"));
    else ui_.key_value("firewalld service journal entries", std::to_string(state.security_signals.firewalld_service_events));

    size_t services = 0, ports = 0, rich_rules = 0, forward_ports = 0; bool forwarding = false, masquerade = false;
    for (const auto& [zone_name, zone] : state.runtime_zones) {
        if (state.active_zone_interfaces.contains(zone_name)) { services += zone.services.size(); ports += zone.ports.size(); rich_rules += zone.rich_rules.size(); forward_ports += zone.forward_ports.size(); }
        forwarding = forwarding || zone.forward; masquerade = masquerade || zone.masquerade;
    }
    ui_.section("Exposure summary");
    ui_.key_value("Allowed services", services == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(services) + " configured"));
    ui_.key_value("Explicit ports", ports == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(ports) + " configured"));
    ui_.key_value("Rich rules", std::to_string(rich_rules));
    ui_.key_value("Forward ports", forward_ports == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(forward_ports) + " configured"));
    ui_.key_value("Forwarding", forwarding ? ui_.warning("ENABLED") : ui_.success("DISABLED"));
    ui_.key_value("Masquerading", masquerade ? ui_.warning("ENABLED") : ui_.success("DISABLED"));
    ui_.key_value("Active policies", state.active_policies.empty() ? ui_.muted("none") : items_or_none(state.active_policies));
}

void Dashboard::show_listeners(const FirewallState& state) const {
    ui_.section("Network-reachable listening sockets");
    if (!state.sockets.available) { std::cout << "  " << ui_.warning("Socket scan is unavailable.") << '\n'; return; }
    bool found = false;
    for (const auto& listener : state.sockets.listeners) {
        if (listener.loopback_only) continue;
        std::cout << "  " << ui_.warning(listener.protocol) << "  " << listener.endpoint << '\n';
        found = true;
    }
    if (!found) std::cout << "  " << ui_.success("No non-loopback listening sockets detected.") << '\n';
}

void Dashboard::show_network_metadata(const NetworkMetadata& metadata, const std::string& history_path) const {
    ui_.section("Public network metadata");
    ui_.key_value("Observed at", metadata.observed_at_utc.empty() ? "unknown" : metadata.observed_at_utc);
    ui_.key_value("Public IP", metadata.public_ip_lookup_succeeded ? ui_.accent(metadata.public_ip) : ui_.warning("lookup failed"));
    ui_.key_value("Default interface", metadata.default_interface.empty() ? "unknown" : metadata.default_interface);
    ui_.key_value("Default gateway", metadata.default_gateway.empty() ? "unknown" : metadata.default_gateway);
    ui_.key_value("Connection profile", metadata.connection_profile.empty() ? "unknown" : metadata.connection_profile);
    if (!metadata.wifi_ssid.empty()) {
        ui_.key_value("Wi-Fi SSID", metadata.wifi_ssid);
        ui_.key_value("Wi-Fi BSSID", metadata.wifi_bssid.empty() ? "unknown" : metadata.wifi_bssid);
        ui_.key_value("Wi-Fi security", metadata.wifi_security.empty() ? "unknown" : metadata.wifi_security);
    }
    if (!metadata.country.empty()) ui_.key_value("Country", metadata.country);
    if (!metadata.timezone.empty()) ui_.key_value("Timezone", metadata.timezone);
    if (!metadata.isp.empty()) ui_.key_value("ISP", metadata.isp);
    if (!metadata.autonomous_system.empty()) ui_.key_value("Autonomous system", metadata.autonomous_system);
    ui_.key_value("History", history_path);
    if (!metadata.diagnostic.empty()) ui_.key_value("Notice", ui_.warning(metadata.diagnostic));
    std::cout << "\n  " << ui_.muted("The public-IP provider received this lookup request.") << '\n';
}

void Dashboard::show_network_history(const std::vector<std::string>& records, const std::string& history_path) const {
    ui_.section("Saved public network metadata");
    ui_.key_value("History", history_path);
    if (records.empty()) { std::cout << "  " << ui_.muted("No saved observations.") << '\n'; return; }
    std::cout << "  " << ui_.muted("timestamp (UTC)  public IP  interface  gateway  profile  SSID  BSSID  security  country  timezone  ISP  ASN  VPN") << '\n';
    for (auto record : records) {
        for (auto& character : record) if (character == '\t') character = ' ';
        std::cout << "  " << record << '\n';
    }
}

void Dashboard::show_network_diagnostics(const NetworkDiagnostics& diagnostics) const {
    ui_.section("Network reachability probes");
    std::cout << "  " << ui_.muted("Two ICMP echo requests are sent to each public resolver.") << '\n';
    for (const auto& probe : diagnostics.probes) {
        const std::string result = !probe.command_available ? ui_.danger("PING UNAVAILABLE") : probe.reachable ? ui_.success("REACHABLE") : ui_.warning("NO REPLY");
        std::cout << "  " << result << "  " << ui_.accent(probe.destination) << '\n';
        if (!probe.output.empty()) std::cout << "    " << probe.output;
        if (!probe.output.empty() && probe.output.back() != '\n') std::cout << '\n';
    }

    ui_.section("Traceroute to 1.1.1.1");
    std::cout << "  " << ui_.muted("Numeric addresses only; one query per hop; maximum 8 hops.") << '\n';
    if (!diagnostics.traceroute_command_available) {
        std::cout << "  " << ui_.danger("traceroute is not installed. Run scripts/setup-firewall-dev.sh to install it.") << '\n';
    } else if (diagnostics.traceroute_output.empty()) {
        std::cout << "  " << ui_.warning("Traceroute produced no output.") << '\n';
    } else {
        std::cout << diagnostics.traceroute_output;
        if (diagnostics.traceroute_output.back() != '\n') std::cout << '\n';
        if (!diagnostics.traceroute_completed) std::cout << "  " << ui_.muted("The route did not complete; timed-out hops are still useful evidence.") << '\n';
    }
    std::cout << "\n  " << ui_.muted("Run only when you intend to generate diagnostic traffic; results do not identify an attacker or network type.") << '\n';
}

void Dashboard::show_security_advisories(const SecurityAdvisoryReport& report) const {
    ui_.section("Available security advisories");
    std::cout << "  " << ui_.muted("Explicit DNF5 query only; no packages, repositories, or firewall settings are changed.") << '\n';
    if (!report.dnf_available) {
        std::cout << "  " << ui_.danger_badge("DNF5 UNAVAILABLE") << " " << ui_.warning(report.diagnostic) << '\n';
        return;
    }
    if (!report.query_succeeded) {
        std::string detail = report.diagnostic;
        for (auto& character : detail) if (static_cast<unsigned char>(character) < 32U || character == '\x7f') character = ' ';
        if (detail.size() > 240) detail.resize(240);
        std::cout << "  " << ui_.warning_badge("QUERY FAILED") << " " << ui_.warning(detail) << '\n';
        return;
    }
    ui_.key_value("Available security advisories", report.advisory_count == 0 ? ui_.success_badge("NONE") : ui_.warning_badge(std::to_string(report.advisory_count)));
    if (report.cves.empty()) {
        ui_.key_value("Referenced CVEs", ui_.muted("none reported by available advisories"));
        return;
    }
    constexpr std::size_t cve_limit = 20;
    std::string cves;
    for (std::size_t index = 0; index < std::min(report.cves.size(), cve_limit); ++index) cves += (cves.empty() ? "" : ", ") + report.cves[index];
    if (report.cves.size() > cve_limit) cves += " … (" + std::to_string(report.cves.size() - cve_limit) + " more)";
    ui_.key_value("Referenced CVEs", ui_.warning(cves));
    std::cout << "\n  " << ui_.muted("Review the advisory and affected package before updating; a CVE reference is not proof of local exploitability.") << '\n';
}

void Dashboard::show_zones(const FirewallState& state, const std::string& title, ZoneView view) const {
    ui_.section(title);
    for (const auto& [name, zone] : state.runtime_zones) {
        std::cout << "  " << ui_.accent(name) << (name == state.default_zone ? ui_.muted("  (default)") : "") << '\n';
        if (view == ZoneView::All) ui_.key_value("target", zone.target.empty() ? "unknown" : zone.target == "ACCEPT" ? ui_.danger(zone.target) : zone.target);
        if (view == ZoneView::All || view == ZoneView::Interfaces) ui_.key_value("interfaces", items_or_none(zone.interfaces));
        if (view == ZoneView::All || view == ZoneView::Interfaces) ui_.key_value("sources", items_or_none(zone.sources));
        if (view == ZoneView::All || view == ZoneView::Services) ui_.key_value("services", items_or_none(zone.services));
        if (view == ZoneView::All || view == ZoneView::Ports) ui_.key_value("ports", items_or_none(zone.ports));
        if (view == ZoneView::All || view == ZoneView::RichRules) ui_.key_value("rich rules", std::to_string(zone.rich_rules.size()));
        if (view == ZoneView::All || view == ZoneView::Routing) ui_.key_value("forward ports", items_or_none(zone.forward_ports));
        if (view == ZoneView::All || view == ZoneView::Routing) {
            ui_.key_value("forwarding", zone.forward ? ui_.warning("enabled") : ui_.success("disabled"));
            ui_.key_value("masquerade", zone.masquerade ? ui_.warning("enabled") : ui_.success("disabled"));
        }
        if (view == ZoneView::Drift) {
            const auto permanent = state.permanent_zones.find(name);
            const bool same = permanent != state.permanent_zones.end() && zone_configurations_equal(zone, permanent->second);
            ui_.key_value("configuration", same ? ui_.success("matches permanent") : ui_.warning("differs from permanent"));
        }
        std::cout << '\n';
    }
}

void Dashboard::show_readiness(const FirewallState& state) const {
    ui_.heading("DEF CON Firewall Readiness", "Read-only assessment — review warnings before connecting to hostile networks");
    for (const auto& check : assess_readiness(state)) {
        const std::string result = check.level == CheckLevel::Pass ? ui_.success_badge("PASS") : check.level == CheckLevel::Warn ? ui_.warning_badge("WARN") : check.level == CheckLevel::Fail ? ui_.danger_badge("FAIL") : ui_.neutral_badge("INFO");
        std::cout << "  " << result << "  " << check.label << (check.detail.empty() ? "" : ui_.muted(" — " + check.detail)) << '\n';
    }
}

void Dashboard::show_menu(const FirewallState& state) const {
    ui_.clear(); ui_.heading("DEF CON FIREWALL CONTROL", "READ-ONLY POSTURE CONSOLE  //  THEME: " + ui_.theme_name()); show_status(state); show_overview(state); ui_.section("Command deck");
    std::cout << "  " << ui_.keycap("1") << " Firewall service state          " << ui_.keycap("6") << " Rich-rule count\n"
              << "  " << ui_.keycap("2") << " Default and active zones        " << ui_.keycap("7") << " Forwarding and masquerading\n"
              << "  " << ui_.keycap("3") << " Interfaces and zone assignments " << ui_.keycap("8") << " Runtime/permanent differences\n"
              << "  " << ui_.keycap("4") << " Allowed services                " << ui_.keycap("9") << " DEF CON readiness report\n"
              << "  " << ui_.keycap("5") << " Explicit open ports             " << ui_.keycap("R") << " Refresh state\n"
              << "  " << ui_.keycap("L") << " Network-reachable listeners\n"
              << "  " << ui_.keycap("D") << " Run ping and traceroute diagnostics (external traffic)\n"
              << "  " << ui_.keycap("S") << " Check available security advisories and CVEs\n"
              << "  " << ui_.keycap("M") << " Query public IP and save metadata (external request)\n"
              << "  " << ui_.keycap("H") << " View saved network metadata\n"
              << "  " << ui_.keycap("0") << " Exit\n";
    ui_.rule(); std::cout << ui_.accent("COMMAND") << " > ";
}

void Dashboard::show_detail_header() const { ui_.clear(); ui_.heading("DEF CON FIREWALL CONTROL", "Read-only detail view"); }
void Dashboard::show_invalid_selection() const { std::cout << ui_.danger("Invalid selection.") << '\n'; }
void Dashboard::show_goodbye() const { std::cout << "\n" << ui_.success("Firewall Control closed. No firewall changes were made.") << '\n'; }
void Dashboard::pause() const { std::cout << '\n' << ui_.muted("Press Enter to return to the dashboard..."); std::string ignored; std::getline(std::cin, ignored); }
} // namespace ffc
