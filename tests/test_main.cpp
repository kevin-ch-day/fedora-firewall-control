#include "ffc/firewall_state.hpp"
#include "ffc/credentials.hpp"
#include "ffc/command_line.hpp"
#include "ffc/port_intelligence.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/security_advisories.hpp"
#include "ffc/terminal_ui.hpp"
#include "ffc/threat_assessment.hpp"
#include "ffc/vpn.hpp"
#include "ffc/readiness.hpp"

#include <cstdlib>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <utility>
#include <vector>

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
class SequencedCommandRunner final : public ffc::CommandRunner {
public:
    explicit SequencedCommandRunner(std::vector<ffc::CommandResult> results) : results_(std::move(results)) {}
    ffc::CommandResult run(const std::vector<std::string>& arguments) const override {
        calls.push_back(arguments);
        if (next_ == results_.size()) return {-1, {}, "unexpected command"};
        return results_[next_++];
    }
    mutable std::vector<std::vector<std::string>> calls;
private:
    std::vector<ffc::CommandResult> results_;
    mutable std::size_t next_{0};
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
    const auto hops = ffc::parse_traceroute_hops("traceroute to 1.1.1.1 (1.1.1.1), 8 hops max\n 1  192.168.0.1  0.5 ms\n 2  100.93.189.130  14.2 ms\n 3  *\n 4  1.1.1.1  22.0 ms\n");
    expect(hops.size() == 3 && hops.front().scope == ffc::NetworkAddressScope::Private && hops.at(1).scope == ffc::NetworkAddressScope::CarrierGradeNat && hops.back().scope == ffc::NetworkAddressScope::Public, "classifies private and carrier-grade NAT traceroute hops");
    const auto malformed_traceroute_hops = ffc::parse_traceroute_hops(" 1  not-an-ip  1.0 ms\n 2  2001:db8::1  2.0 ms\n 999999999999999999999  1.1.1.1  3.0 ms\n");
    expect(malformed_traceroute_hops.size() == 1 && malformed_traceroute_hops.front().scope == ffc::NetworkAddressScope::SpecialUse, "rejects malformed numeric traceroute output while retaining valid special-use route data");
    const auto corrupt_traceroute_hops = ffc::parse_traceroute_hops(" 0  1.1.1.1  1.0 ms\n -1  1.1.1.1  1.0 ms\n 3  \x1b[31m1.1.1.1  1.0 ms\n 4  8.8.8.8  1.0 ms\n");
    expect(corrupt_traceroute_hops.size() == 1 && corrupt_traceroute_hops.front().number == 4, "rejects zero, negative, overflow, and control-byte traceroute hop data");
    const auto mtr_hops = ffc::parse_mtr_hops(" 1.|-- 192.168.0.1  0.0%     5  0.5  0.6  0.4  0.8  0.1\n 2.|-- 100.93.189.131  0.0%     5 12.0 12.6 11.9 13.2  0.5\n 3.|-- ??? 100.0     5  0.0  0.0  0.0  0.0  0.0\n11.|-- 1.1.1.1  0.0%     5 22.0 23.1 21.9 24.0  0.9\n");
    expect(mtr_hops.size() == 4 && mtr_hops.at(1).scope == ffc::NetworkAddressScope::CarrierGradeNat && mtr_hops.at(2).response_loss_percent == 100.0 && mtr_hops.back().scope == ffc::NetworkAddressScope::Public, "parses MTR response-loss data without treating intermediate loss as endpoint loss");
    const auto malformed_mtr_hops = ffc::parse_mtr_hops(" 1.|-- 192.168.0.1 nan%\n 2.|-- 198.51.100.4 101.0%\n 3.|-- 1.1.1.1 -1.0%\n 4.|-- 1.1.1.1 0.0%\n");
    expect(malformed_mtr_hops.size() == 1 && malformed_mtr_hops.front().number == 4, "rejects malformed, non-finite, and out-of-range MTR loss values");
    const auto malformed_mtr_address_hops = ffc::parse_mtr_hops(" 1.|-- not-an-ip  0.0%\n 2.|-- ??? 100.0\n");
    expect(malformed_mtr_address_hops.size() == 1 && malformed_mtr_address_hops.front().address == "???", "retains only MTR's explicit no-reply marker when a hop address is invalid");
    const auto corrupt_mtr_hops = ffc::parse_mtr_hops(" 0.|-- 1.1.1.1  0.0%\n 1.|-- ??? 0.0%\n 2.|-- 1.1.1.1 1e2%\n 3.|-- 1.1.1.1 0x1p0%\n 4.|-- 8.8.8.8 100.0%\n");
    expect(corrupt_mtr_hops.size() == 1 && corrupt_mtr_hops.front().number == 4 && corrupt_mtr_hops.front().response_loss_percent == 100.0, "accepts only valid MTR hop numbers, decimal loss fields, and timeout semantics");
    expect(ffc::classify_network_address("0.0.0.0") == ffc::NetworkAddressScope::SpecialUse && ffc::classify_network_address("198.51.100.25") == ffc::NetworkAddressScope::SpecialUse && ffc::classify_network_address("2001:db8::1") == ffc::NetworkAddressScope::SpecialUse, "does not label documentation and special-use addresses as public routes");
    expect(ffc::classify_network_address("::1") == ffc::NetworkAddressScope::Loopback && ffc::classify_network_address("fe80::1") == ffc::NetworkAddressScope::LinkLocal && ffc::classify_network_address("not-an-address") == ffc::NetworkAddressScope::Unknown, "classifies IPv6 and invalid route addresses conservatively");
    expect(ffc::classify_network_address("::ffff:192.168.1.20") == ffc::NetworkAddressScope::Private && ffc::classify_network_address("::ffff:100.64.0.1") == ffc::NetworkAddressScope::CarrierGradeNat, "classifies IPv4-mapped IPv6 addresses by their embedded IPv4 scope");
    expect(ffc::classify_network_address("10.255.255.255") == ffc::NetworkAddressScope::Private && ffc::classify_network_address("11.0.0.0") == ffc::NetworkAddressScope::Public && ffc::classify_network_address("172.15.255.255") == ffc::NetworkAddressScope::Public && ffc::classify_network_address("172.16.0.0") == ffc::NetworkAddressScope::Private && ffc::classify_network_address("172.31.255.255") == ffc::NetworkAddressScope::Private && ffc::classify_network_address("172.32.0.0") == ffc::NetworkAddressScope::Public, "honors private IPv4 range boundaries");
    expect(ffc::classify_network_address("100.63.255.255") == ffc::NetworkAddressScope::Public && ffc::classify_network_address("100.64.0.0") == ffc::NetworkAddressScope::CarrierGradeNat && ffc::classify_network_address("100.127.255.255") == ffc::NetworkAddressScope::CarrierGradeNat && ffc::classify_network_address("100.128.0.0") == ffc::NetworkAddressScope::Public, "honors carrier-grade NAT range boundaries");
    expect(ffc::classify_network_address("224.0.0.0") == ffc::NetworkAddressScope::Multicast && ffc::classify_network_address("239.255.255.255") == ffc::NetworkAddressScope::Multicast && ffc::classify_network_address("240.0.0.0") == ffc::NetworkAddressScope::SpecialUse && ffc::network_address_scope_label(ffc::NetworkAddressScope::SpecialUse) == "special-use address", "distinguishes multicast, special-use, and public route semantics");
    SequencedCommandRunner basic_diagnostics_runner({{0, "first ping", {}}, {0, "second ping", {}}, {0, " 1  1.1.1.1  10.0 ms\n", {}}});
    const auto basic_diagnostics = ffc::ConnectivityAssessment(basic_diagnostics_runner).inspect();
    expect(basic_diagnostics.probes.size() == 2 && basic_diagnostics.traceroutes.size() == 1 && basic_diagnostics.traceroutes.front().completed && !basic_diagnostics.path_stability && basic_diagnostics_runner.calls.size() == 3, "runs only the basic bounded diagnostic plan by default");
    expect(basic_diagnostics_runner.calls.at(0).front() == "ping" && basic_diagnostics_runner.calls.at(2).front() == "traceroute", "uses explicit non-shell diagnostic commands");
    SequencedCommandRunner partial_route_runner({{0, "first ping", {}}, {0, "second ping", {}}, {0, " 1  192.168.0.1  1.0 ms\n", "route did not reach target"}});
    const auto partial_route_diagnostics = ffc::ConnectivityAssessment(partial_route_runner).inspect();
    expect(!partial_route_diagnostics.traceroutes.front().completed && partial_route_diagnostics.traceroutes.front().output.find("route did not reach target") != std::string::npos, "does not mistake a successful traceroute process for a completed route");
    SequencedCommandRunner extended_diagnostics_runner({{0, "first ping", {}}, {0, "second ping", {}}, {0, " 1  1.1.1.1  10.0 ms\n", {}}, {0, " 1  8.8.8.8  10.0 ms\n", {}}, {0, " 1  9.9.9.9  10.0 ms\n", {}}, {0, " 1  208.67.222.222  10.0 ms\n", {}}});
    const auto extended_diagnostics_report = ffc::ConnectivityAssessment(extended_diagnostics_runner).inspect(true, false);
    expect(extended_diagnostics_report.traceroutes.size() == 4 && !extended_diagnostics_report.path_stability && extended_diagnostics_report.resolver_probes.empty() && extended_diagnostics_runner.calls.size() == 6, "extended diagnostics does not silently run advanced probes");
    SequencedCommandRunner advanced_diagnostics_runner({{0, "first ping", {}}, {0, "second ping", {}}, {0, " 1  1.1.1.1  10.0 ms\n", {}}, {0, " 1  8.8.8.8  10.0 ms\n", {}}, {0, " 1  9.9.9.9  10.0 ms\n", {}}, {0, " 1  208.67.222.222  10.0 ms\n", {}}, {0, " 1.|-- 1.1.1.1  0.0%\n", {}}, {0, "status: NOERROR", {}}, {0, "status: NOERROR", {}}, {0, "status: NOERROR", {}}});
    const auto advanced_diagnostics_report = ffc::ConnectivityAssessment(advanced_diagnostics_runner).inspect(false, true);
    expect(advanced_diagnostics_report.traceroutes.size() == 4 && advanced_diagnostics_report.path_stability && advanced_diagnostics_report.path_stability->destination_observed && advanced_diagnostics_report.resolver_probes.size() == 3 && advanced_diagnostics_runner.calls.size() == 10, "advanced diagnostics adds the documented bounded probe plan");
    expect(advanced_diagnostics_runner.calls.at(6).front() == "mtr" && advanced_diagnostics_runner.calls.at(7).front() == "dig", "advanced diagnostics invokes MTR and direct DNS only in advanced mode");
    SequencedCommandRunner unavailable_tool_runner({{127, {}, "ping unavailable"}, {127, {}, "ping unavailable"}, {127, {}, "traceroute unavailable"}});
    const auto unavailable_diagnostics = ffc::ConnectivityAssessment(unavailable_tool_runner).inspect();
    expect(!unavailable_diagnostics.probes.front().command_available && !unavailable_diagnostics.traceroutes.front().command_available, "marks unavailable diagnostic tools without treating them as hostile network evidence");
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
    const auto extended_diagnostics = ffc::parse_command_line({"--network-diagnostics", "--extended"});
    expect(extended_diagnostics.action == ffc::CommandAction::NetworkDiagnostics && extended_diagnostics.extended_diagnostics, "parses extended diagnostics command");
    const auto advanced_diagnostics = ffc::parse_command_line({"--network-diagnostics", "--advanced"});
    expect(advanced_diagnostics.action == ffc::CommandAction::NetworkDiagnostics && advanced_diagnostics.extended_diagnostics && advanced_diagnostics.advanced_diagnostics, "parses advanced diagnostics command");
    expect(ffc::parse_command_line({"--network-diagnostics", "--extended", "extra"}).action == ffc::CommandAction::Invalid && ffc::parse_command_line({"--network-diagnostics", "--unknown"}).action == ffc::CommandAction::Invalid, "rejects unsupported diagnostic option combinations");
    const auto hostile_mode = ffc::parse_command_line({"--mode", "hostile"});
    expect(hostile_mode.action == ffc::CommandAction::Mode && hostile_mode.mode_to_set == ffc::OperatingMode::HostileNetwork, "parses hostile mode command");
    expect(ffc::parse_command_line({"--network-metadata", "--unexpected"}).action == ffc::CommandAction::Invalid, "rejects invalid command combinations");
    expect(ffc::parse_command_line({"--threat-assessment"}).action == ffc::CommandAction::ThreatAssessment, "parses threat assessment command");
    bool parser_fuzz_invariants_hold = true;
    std::uint32_t fuzz_state = 0x7f4a7c15U;
    for (unsigned int sample = 0; sample < 1000U; ++sample) {
        std::string noise;
        const auto length = (fuzz_state % 257U) + 1U;
        for (unsigned int index = 0; index < length; ++index) {
            fuzz_state = fuzz_state * 1664525U + 1013904223U;
            noise.push_back(static_cast<char>(fuzz_state & 0xffU));
        }
        for (const auto& hop : ffc::parse_traceroute_hops(noise)) parser_fuzz_invariants_hold = parser_fuzz_invariants_hold && hop.number > 0U && hop.scope != ffc::NetworkAddressScope::Unknown;
        for (const auto& hop : ffc::parse_mtr_hops(noise)) parser_fuzz_invariants_hold = parser_fuzz_invariants_hold && hop.number > 0U && hop.response_loss_percent && std::isfinite(*hop.response_loss_percent) && *hop.response_loss_percent >= 0.0 && *hop.response_loss_percent <= 100.0 && (hop.address != "???" || *hop.response_loss_percent == 100.0) && (hop.address == "???" || hop.scope != ffc::NetworkAddressScope::Unknown);
    }
    const std::string oversized_corrupt_line(65536U, '\x1b');
    parser_fuzz_invariants_hold = parser_fuzz_invariants_hold && ffc::parse_traceroute_hops(oversized_corrupt_line).empty() && ffc::parse_mtr_hops(oversized_corrupt_line).empty();
    expect(parser_fuzz_invariants_hold, "maintains route-parser safety invariants across deterministic binary fuzz input");
    const ffc::ProcessCommandRunner process_runner;
    const auto empty_command_result = process_runner.run({});
    const auto stderr_command_result = process_runner.run({"/bin/sh", "-c", "printf stdout; printf stderr >&2; exit 7"});
    const auto missing_command_result = process_runner.run({"ffc-command-that-does-not-exist"});
    const auto signaled_command_result = process_runner.run({"/bin/sh", "-c", "kill -TERM $$"});
    const auto closed_input_result = process_runner.run_with_input({"/bin/sh", "-c", "exec 0<&-; sleep 0.05"}, std::string(128U * 1024U, 'x'));
    const auto unread_input_result = process_runner.run_with_input({"/bin/sh", "-c", "sleep 0.05"}, std::string(128U * 1024U, 'x'));
    const auto excessive_output_result = process_runner.run({"/bin/sh", "-c", "head -c 1048577 /dev/zero"});
    expect(empty_command_result.exit_code == -1 && !empty_command_result.stderr_text.empty(), "rejects an empty process command safely");
    expect(stderr_command_result.exit_code == 7 && stderr_command_result.stdout_text == "stdout" && stderr_command_result.stderr_text == "stderr", "captures independent stdout, stderr, and exit status");
    expect(missing_command_result.exit_code == 127, "reports an unavailable executable without invoking a shell");
    expect(signaled_command_result.exit_code == -1, "reports a child terminated by signal as a failed command");
    expect(closed_input_result.exit_code == -1 && closed_input_result.stderr_text.find("did not accept all standard input") != std::string::npos, "survives and reports a child process that closes stdin before consuming input");
    expect(unread_input_result.exit_code == -1 && unread_input_result.stderr_text.find("did not accept all standard input") != std::string::npos, "does not indefinitely block when a child keeps stdin open but never reads it");
    expect(excessive_output_result.exit_code == -1 && excessive_output_result.stdout_text.size() == 1024U * 1024U && excessive_output_result.stderr_text.find("output exceeded 1 MiB safety limit") != std::string::npos, "terminates and bounds excessively noisy child processes");
    const ffc::TerminalUi plain_ui;
    expect(plain_ui.success_badge("READY") == "[ READY ]" && plain_ui.keycap("R") == "[ R ]", "keeps status badges legible without color");
    expect(ffc::ReadinessCheck{}.level == ffc::CheckLevel::Info, "default-constructs readiness checks with a safe informational level");
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
