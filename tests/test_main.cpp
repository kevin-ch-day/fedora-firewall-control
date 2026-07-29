#include "ffc/firewall_state.hpp"
#include "ffc/credentials.hpp"
#include "ffc/command_line.hpp"
#include "ffc/port_intelligence.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/security_advisories.hpp"
#include "ffc/terminal_ui.hpp"
#include "ffc/threat_assessment.hpp"
#include "ffc/vpn.hpp"
#include "ffc/readiness.hpp"

#include <cstdlib>
#include <iostream>

namespace {
int failures = 0;
void expect(bool value, const char* text) { if (!value) { std::cerr << "FAILED: " << text << '\n'; ++failures; } }
class StubCommandRunner final : public ffc::CommandRunner {
public:
    explicit StubCommandRunner(ffc::CommandResult result) : result_(std::move(result)) {}
    ffc::CommandResult run(const std::vector<std::string>&) const override { return result_; }
private:
    ffc::CommandResult result_;
};
}
int main() {
    const auto zone = ffc::parse_zone_info("target: ACCEPT\ninterfaces: enp1s0 wlp2s0\nsources: 192.0.2.0/24\nservices: ssh dhcpv6-client\nports: 8080/tcp\nforward-ports:\n  port=8080:proto=tcp:toport=80\nmasquerade: yes\nforward: no\n  rule family=\"ipv4\" service name=\"ssh\" accept\n");
    expect(zone.target == "ACCEPT", "parses target"); expect(zone.interfaces.size() == 2, "parses interfaces"); expect(zone.sources.size() == 1, "parses sources"); expect(zone.services.size() == 2, "parses services"); expect(zone.ports == std::vector<std::string>{"8080/tcp"}, "parses ports"); expect(zone.forward_ports.size() == 1, "parses forward ports"); expect(zone.masquerade && !zone.forward, "parses booleans"); expect(zone.rich_rules.size() == 1, "counts rich rules");
    auto policy_match_with_runtime_interface = zone;
    policy_match_with_runtime_interface.interfaces.clear();
    expect(!ffc::zone_configurations_equal(zone, policy_match_with_runtime_interface) && ffc::zone_policies_equal(zone, policy_match_with_runtime_interface), "separates dynamic interface assignment from policy drift");
    const auto active_output = "public (default)\n  interfaces: wlp0s20f3\n  sources: 192.0.2.0/24\ntrusted\n  interfaces: enp1s0\n";
    const auto active_zones = ffc::parse_active_zones(active_output);
    expect(active_zones.size() == 2 && active_zones.at("public") == std::vector<std::string>{"wlp0s20f3"}, "parses active zones");
    const auto active_sources = ffc::parse_active_zone_sources(active_output);
    expect(active_sources.at("public") == std::vector<std::string>{"192.0.2.0/24"}, "parses active sources");
    expect(ffc::parse_active_policy_names("allow-host-ipv6\n  ingress-zones: ANY\n  egress-zones: HOST\n").size() == 1, "parses active policies");
    const auto devices = ffc::parse_network_manager_devices("wlp0s20f3:wifi:connected\nenp1s0:ethernet:disconnected\n");
    expect(devices.size() == 2 && devices.front().state == "connected", "parses NetworkManager devices");
    const auto tunnels = ffc::parse_vpn_tunnel_interfaces("5: nordlynx: <POINTOPOINT,UP> mtu 1420\n6: wg0: <POINTOPOINT,UP> mtu 1420\n7: enp1s0: <BROADCAST,UP> mtu 1500\n");
    expect(tunnels == std::vector<std::string>{"nordlynx", "wg0"}, "parses VPN tunnel interfaces");
    const auto sockets = ffc::parse_listening_sockets("tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=120,fd=7))\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:((\"avahi-daemon\",pid=121,fd=8))\nudp UNCONN 0 0 239.255.255.250:3702 0.0.0.0:* users:((\"wsdd\",pid=122,fd=9))\n");
    ffc::SocketState socket_state; socket_state.available = true; socket_state.listeners = sockets;
    const auto socket_summary = ffc::summarize_listener_exposure(socket_state);
    expect(sockets.size() == 3 && sockets.front().loopback_only && !sockets.at(1).loopback_only && sockets.at(1).process_name == "avahi-daemon" && sockets.back().multicast_only, "classifies listener scope and retains process name only");
    expect(socket_summary.logical_network_services == 1 && socket_summary.network_reachable_bindings == 1 && socket_summary.multicast_only_bindings == 1, "excludes multicast-only discovery bindings from exposed-service count");
    expect(ffc::count_journal_entries("-- Boot abc --\nJul 1 kernel: DROP packet\n-- No entries --\n") == 1, "counts journal signals");
    const auto denial_summary = ffc::summarize_kernel_denials("Jul 1 kernel: DROP SRC=192.0.2.1 DPT=22\nJul 1 kernel: REJECT SRC=192.0.2.2 DPT=443\nJul 1 kernel: DROP SRC=192.0.2.1 DPT=22\n");
    expect(denial_summary.event_count == 3 && denial_summary.unique_sources == 2 && denial_summary.unique_destination_ports == 2, "summarizes denial telemetry without retaining values");
    const auto metadata = ffc::parse_default_route("default via 192.0.2.1 dev wlp0s20f3 proto dhcp metric 600\n");
    expect(metadata.default_gateway == "192.0.2.1" && metadata.default_interface == "wlp0s20f3", "parses default route");
    expect(ffc::is_valid_ip_address("203.0.113.5") && ffc::is_valid_ip_address("2001:db8::1") && !ffc::is_valid_ip_address("not-an-ip"), "validates public IP values");
    const auto ssh_port = ffc::identify_port_spec("22/tcp");
    const auto rdp_port = ffc::identify_port_spec("3389/TCP");
    const auto radius_port = ffc::identify_port_spec("1812/udp");
    const auto mdns_port = ffc::identify_endpoint("0.0.0.0:5353", "udp");
    const auto application_range = ffc::identify_port_spec("8000-8010/tcp");
    const auto modbus_port = ffc::identify_port_spec("502/tcp");
    const auto active_directory_port = ffc::identify_port_spec("3269/tcp");
    const auto kubernetes_port = ffc::identify_port_spec("10250/tcp");
    const auto dhcpv6_port = ffc::identify_port_spec("547/udp");
    const auto cellular_port = ffc::identify_port_spec("38412/sctp");
    const auto telemetry_port = ffc::identify_port_spec("4317/tcp");
    const auto vnc_display_port = ffc::identify_port_spec("5907/tcp");
    const auto node_port = ffc::identify_port_spec("31080/tcp");
    const auto wireguard_port = ffc::identify_endpoint("[::]:51820", "udp");
    const auto dynamic_port = ffc::identify_endpoint("0.0.0.0:55000", "udp");
    expect(ssh_port.range == ffc::PortRange::WellKnown && ssh_port.likely_service == "SSH remote administration", "identifies SSH as a well-known port");
    expect(ssh_port.source == ffc::PortKnowledgeSource::Curated, "marks curated port knowledge");
    expect(rdp_port.likely_service == "RDP remote desktop", "normalizes protocol before recognizing RDP");
    expect(radius_port.range == ffc::PortRange::Registered && radius_port.likely_service == "RADIUS authentication", "identifies registered infrastructure ports");
    expect(mdns_port.likely_service == "mDNS discovery", "identifies local discovery ports");
    expect(application_range.port == 8000 && application_range.range_end == 8010 && application_range.likely_service == "port range (individual services vary)", "handles firewalld port ranges without guessing a service");
    expect(modbus_port.likely_service == "Modbus industrial control", "recognizes industrial control ports");
    expect(active_directory_port.likely_service == "Active Directory global catalog over TLS", "recognizes directory infrastructure ports");
    expect(kubernetes_port.likely_service == "Kubernetes kubelet API", "recognizes container orchestration ports");
    expect(dhcpv6_port.likely_service == "DHCPv6 server", "recognizes IPv6 infrastructure ports");
    expect(cellular_port.likely_service == "NGAP 5G signaling", "recognizes SCTP services");
    expect(telemetry_port.likely_service == "OpenTelemetry gRPC collector", "recognizes modern telemetry ports");
    expect(vnc_display_port.likely_service == "VNC remote desktop display range", "recognizes conventional VNC ranges");
    expect(node_port.likely_service == "Kubernetes NodePort default range", "recognizes conventional Kubernetes node port range");
    expect(wireguard_port.range == ffc::PortRange::DynamicPrivate, "classifies WireGuard port range");
    expect(wireguard_port.likely_service == "WireGuard", "maps WireGuard port name");
    expect(dynamic_port.range == ffc::PortRange::DynamicPrivate, "identifies dynamic/private ports");
    expect(ffc::is_valid_ipify_api_key("at_example_key-123") && !ffc::is_valid_ipify_api_key("") && !ffc::is_valid_ipify_api_key("contains a space"), "validates Geo ipify key format");
    expect(ffc::parse_command_line({}).action == ffc::CommandAction::Interactive, "parses interactive command");
    const auto enrich_command = ffc::parse_command_line({"--network-metadata", "--enrich"});
    expect(enrich_command.action == ffc::CommandAction::NetworkMetadata && enrich_command.enrich_metadata, "parses metadata enrichment command");
    const auto hostile_mode = ffc::parse_command_line({"--mode", "hostile"});
    expect(hostile_mode.action == ffc::CommandAction::Mode && hostile_mode.mode_to_set == ffc::OperatingMode::HostileNetwork, "parses hostile mode command");
    expect(ffc::parse_command_line({"--network-metadata", "--unexpected"}).action == ffc::CommandAction::Invalid, "rejects invalid command combinations");
    expect(ffc::parse_command_line({"--threat-assessment"}).action == ffc::CommandAction::ThreatAssessment, "parses threat assessment command");
    const ffc::TerminalUi plain_ui;
    expect(plain_ui.success_badge("READY") == "[ READY ]" && plain_ui.keycap("R") == "[ R ]", "keeps status badges legible without color");
    StubCommandRunner advisory_runner({0, R"([{"advisory_name":"FEDORA-test","references":[{"reference_id":"CVE-2026-1234"},{"reference_id":"CVE-2026-1234"},{"reference_id":"CVE-2025-9999"}]}])", {}});
    const auto advisory_report = ffc::SecurityAdvisoryInspector(advisory_runner).inspect();
    expect(advisory_report.query_succeeded && advisory_report.advisory_count == 1 && advisory_report.cves == std::vector<std::string>{"CVE-2025-9999", "CVE-2026-1234"}, "summarizes available CVE advisories");
    ffc::FirewallState state; state.installed = state.active = state.enabled = state.permanent_config_checked = state.permanent_config_valid = true; state.default_zone = "public"; state.runtime_zones["public"] = zone; state.permanent_zones["public"] = zone; state.active_zone_interfaces = active_zones; state.active_zone_sources = active_sources;
    const auto checks = ffc::assess_readiness(state); bool found_masquerade = false, found_accept = false; for (const auto& check : checks) { if (check.label == "masquerading disabled") found_masquerade = check.level == ffc::CheckLevel::Warn; if (check.label == "active zone target") found_accept = check.level == ffc::CheckLevel::Fail; }
    expect(found_masquerade, "flags masquerading"); expect(found_accept, "flags ACCEPT target");
    state.log_denied = "off";
    state.sockets.available = true;
    state.sockets.listeners = {{"tcp", "0.0.0.0:22", false, false, {}}};
    state.security_signals.kernel_journal_available = true;
    state.active_zone_sources.clear();
    state.permanent_zones["public"].target = "DROP";
    state.runtime_zones["public"].ports = {"1025-65535/tcp"};
    state.runtime_zones["public"].forward = true;
    const auto threat_assessment = ffc::assess_threat_evidence(state);
    bool has_logging_gap = false, has_listener_exposure = false, has_drift_candidate = false, has_broad_range = false, has_forwarding_context = false;
    for (const auto& finding : threat_assessment.findings) {
        has_logging_gap = has_logging_gap || (finding.kind == ffc::ThreatFindingKind::CoverageGap && finding.title == "Denied-packet logging is off");
        has_listener_exposure = has_listener_exposure || (finding.kind == ffc::ThreatFindingKind::Exposure && finding.title == "Network-reachable local listeners");
        has_drift_candidate = has_drift_candidate || (finding.kind == ffc::ThreatFindingKind::CandidateAlert && finding.title == "Firewall runtime/permanent drift");
        has_broad_range = has_broad_range || (finding.kind == ffc::ThreatFindingKind::Exposure && finding.title == "Broad inbound port range configured");
        has_forwarding_context = has_forwarding_context || (finding.kind == ffc::ThreatFindingKind::NoAlert && finding.title == "Intra-zone forwarding has no current path");
    }
    expect(has_logging_gap && has_listener_exposure && has_drift_candidate && has_broad_range && has_forwarding_context, "separates coverage gaps, exposure, broad policy, and unverified candidates");
    expect(threat_assessment.verdict_rules.size() == 4, "explains all four ground-truth verdicts");
    state.security_signals.kernel_drop_or_reject_events = 2;
    const auto incomplete_but_active_telemetry = ffc::assess_threat_evidence(state);
    bool has_denial_candidate = false;
    for (const auto& finding : incomplete_but_active_telemetry.findings) has_denial_candidate = has_denial_candidate || finding.title == "Denied-packet activity observed";
    expect(has_denial_candidate, "keeps separately logged denial events visible when default logging is off");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
