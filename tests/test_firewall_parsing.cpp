#include "test_support.hpp"

#include "ffc/firewall_state.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/vpn.hpp"

#include <vector>

namespace ffc::test {
void run_firewall_parsing_tests() {
    const auto zone = parse_zone_info("target: ACCEPT\ninterfaces: enp1s0 wlp2s0\nsources: 192.0.2.0/24\nservices: ssh dhcpv6-client\nports: 8080/tcp\nforward-ports:\n port=8080:proto=tcp:toport=80\nmasquerade: yes\nforward: no\n rule family=\"ipv4\" service name=\"ssh\" accept\n");
    expect(zone.target == "ACCEPT" && zone.interfaces.size() == 2 && zone.sources.size() == 1 && zone.services.size() == 2 && zone.ports == std::vector<std::string>{"8080/tcp"} && zone.forward_ports.size() == 1 && zone.masquerade && !zone.forward && zone.rich_rules.size() == 1, "parses complete firewalld zone details");
    const auto all_zones = parse_all_zone_info("work (default, active)\n target: default\n interfaces: enp1s0\n services: ssh\n ports: 22/tcp\n\ntrusted\n target: ACCEPT\n interfaces: \n services: \n ports: \n");
    expect(all_zones.size() == 2 && all_zones.at("work").interfaces == std::vector<std::string>{"enp1s0"} && all_zones.at("trusted").target == "ACCEPT", "parses bulk firewalld zone output");
    auto policy_match = zone; policy_match.interfaces.clear();
    expect(!zone_configurations_equal(zone, policy_match) && zone_policies_equal(zone, policy_match), "separates dynamic interface assignment from policy drift");
    const auto active = "public (default)\n interfaces: wlp0s20f3\n sources: 192.0.2.0/24\ntrusted\n interfaces: enp1s0\n";
    expect(parse_active_zones(active).at("public") == std::vector<std::string>{"wlp0s20f3"} && parse_active_zone_sources(active).at("public") == std::vector<std::string>{"192.0.2.0/24"} && parse_active_policy_names("allow-host-ipv6\n ingress-zones: ANY\n").size() == 1, "parses active firewall state");
    expect(parse_network_manager_devices("wlp0s20f3:wifi:connected\n").front().state == "connected" && parse_vpn_tunnel_interfaces("5: nordlynx: <UP>\n6: wg0: <UP>\n") == std::vector<std::string>{"nordlynx", "wg0"}, "parses device and VPN state");
    const auto sockets = parse_listening_sockets("tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\"))\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:((\"avahi-daemon\"))\nudp UNCONN 0 0 239.255.255.250:3702 0.0.0.0:* users:((\"wsdd\"))\n");
    SocketState state; state.available = true; state.listeners = sockets;
    const auto exposure = summarize_listener_exposure(state);
    expect(sockets.size() == 3 && sockets.front().loopback_only && !sockets.at(1).loopback_only && sockets.back().multicast_only && exposure.logical_network_services == 1 && exposure.network_reachable_bindings == 1, "classifies listener exposure conservatively");
    expect(count_journal_entries("-- Boot --\nDROP packet\n-- No entries --\n") == 1 && summarize_kernel_denials("DROP SRC=192.0.2.1 DPT=22\nREJECT SRC=192.0.2.2 DPT=443\n").unique_sources == 2, "summarizes firewall telemetry without retaining values");
    const auto route = parse_default_route("default via 192.0.2.1 dev wlp0s20f3 proto dhcp\n");
    expect(route.default_gateway == "192.0.2.1" && route.default_interface == "wlp0s20f3" && is_valid_ip_address("2001:db8::1") && !is_valid_ip_address("bad"), "parses default-route metadata");
}
} // namespace ffc::test
