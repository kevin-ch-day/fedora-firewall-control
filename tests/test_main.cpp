#include "ffc/firewall_state.hpp"
#include "ffc/credentials.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/vpn.hpp"
#include "ffc/readiness.hpp"

#include <cstdlib>
#include <iostream>

namespace { int failures = 0; void expect(bool value, const char* text) { if (!value) { std::cerr << "FAILED: " << text << '\n'; ++failures; } } }
int main() {
    const auto zone = ffc::parse_zone_info("target: ACCEPT\ninterfaces: enp1s0 wlp2s0\nsources: 192.0.2.0/24\nservices: ssh dhcpv6-client\nports: 8080/tcp\nforward-ports:\n  port=8080:proto=tcp:toport=80\nmasquerade: yes\nforward: no\n  rule family=\"ipv4\" service name=\"ssh\" accept\n");
    expect(zone.target == "ACCEPT", "parses target"); expect(zone.interfaces.size() == 2, "parses interfaces"); expect(zone.sources.size() == 1, "parses sources"); expect(zone.services.size() == 2, "parses services"); expect(zone.ports == std::vector<std::string>{"8080/tcp"}, "parses ports"); expect(zone.forward_ports.size() == 1, "parses forward ports"); expect(zone.masquerade && !zone.forward, "parses booleans"); expect(zone.rich_rules.size() == 1, "counts rich rules");
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
    const auto sockets = ffc::parse_listening_sockets("tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n");
    expect(sockets.size() == 2 && sockets.front().loopback_only && !sockets.back().loopback_only, "classifies listening sockets");
    expect(ffc::count_journal_entries("-- Boot abc --\nJul 1 kernel: DROP packet\n-- No entries --\n") == 1, "counts journal signals");
    const auto metadata = ffc::parse_default_route("default via 192.0.2.1 dev wlp0s20f3 proto dhcp metric 600\n");
    expect(metadata.default_gateway == "192.0.2.1" && metadata.default_interface == "wlp0s20f3", "parses default route");
    expect(ffc::is_valid_ip_address("203.0.113.5") && ffc::is_valid_ip_address("2001:db8::1") && !ffc::is_valid_ip_address("not-an-ip"), "validates public IP values");
    expect(ffc::is_valid_ipify_api_key("at_example_key-123") && !ffc::is_valid_ipify_api_key("") && !ffc::is_valid_ipify_api_key("contains a space"), "validates Geo ipify key format");
    ffc::FirewallState state; state.installed = state.active = state.enabled = state.permanent_config_checked = state.permanent_config_valid = true; state.default_zone = "public"; state.runtime_zones["public"] = zone; state.permanent_zones["public"] = zone; state.active_zone_interfaces = active_zones; state.active_zone_sources = active_sources;
    const auto checks = ffc::assess_readiness(state); bool found_masquerade = false, found_accept = false; for (const auto& check : checks) { if (check.label == "masquerading disabled") found_masquerade = check.level == ffc::CheckLevel::Warn; if (check.label == "active zone target") found_accept = check.level == ffc::CheckLevel::Fail; }
    expect(found_masquerade, "flags masquerading"); expect(found_accept, "flags ACCEPT target"); return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
