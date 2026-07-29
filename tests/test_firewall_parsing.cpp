#include "test_support.hpp"

#include "ffc/firewall_state.hpp"
#include "ffc/firewalld_backend.hpp"
#include "ffc/readiness.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/vpn.hpp"

#include <string>
#include <vector>

namespace ffc::test {
void run_firewall_parsing_tests() {
    const auto zone = parse_zone_info(
        "target: ACCEPT\ninterfaces: enp1s0 wlp2s0\nsources: 192.0.2.0/24\nservices: ssh "
        "dhcpv6-client\nports: 8080/tcp\nprotocols: esp\nsource-ports: "
        "1024-65535\nforward-ports:\n port=8080:proto=tcp:toport=80\nmasquerade: yes\nforward: "
        "no\n rule family=\"ipv4\" service name=\"ssh\" accept\n");
    expect(zone.target == "ACCEPT" && zone.interfaces.size() == 2 && zone.sources.size() == 1 &&
               zone.services.size() == 2 && zone.ports == std::vector<std::string>{"8080/tcp"} &&
               zone.protocols == std::vector<std::string>{"esp"} &&
               zone.source_ports == std::vector<std::string>{"1024-65535"} &&
               zone.forward_ports.size() == 1 && zone.masquerade && !zone.forward &&
               zone.rich_rules.size() == 1,
           "parses complete firewalld zone details");
    const auto all_zones = parse_all_zone_info(
        "work (default, active)\n target: default\n interfaces: enp1s0\n services: ssh\n ports: "
        "22/tcp\n\ntrusted\n target: ACCEPT\n interfaces: \n services: \n ports: \n");
    expect(all_zones.size() == 2 &&
               all_zones.at("work").interfaces == std::vector<std::string>{"enp1s0"} &&
               all_zones.at("trusted").target == "ACCEPT",
           "parses bulk firewalld zone output");
    auto policy_match = zone;
    policy_match.interfaces.clear();
    expect(!zone_configurations_equal(zone, policy_match) &&
               zone_policies_equal(zone, policy_match),
           "separates dynamic interface assignment from policy drift");
    const auto active = "public (default)\n interfaces: wlp0s20f3\n sources: "
                        "192.0.2.0/24\ntrusted\n interfaces: enp1s0\n";
    expect(parse_active_zones(active).at("public") == std::vector<std::string>{"wlp0s20f3"} &&
               parse_active_zone_sources(active).at("public") ==
                   std::vector<std::string>{"192.0.2.0/24"} &&
               parse_active_policy_names("allow-host-ipv6\n ingress-zones: ANY\n").size() == 1 &&
               parse_active_policy_names("\033[31mevil\n").front() == "?[31mevil",
           "parses active firewall state");
    expect(parse_network_manager_devices("wlp0s20f3:wifi:connected\n").front().state ==
                   "connected" &&
               parse_vpn_tunnel_interfaces("5: nordlynx: <UP>\n6: wg0: <UP>\n") ==
                   std::vector<std::string>{"nordlynx", "wg0"},
           "parses device and VPN state");
    const auto sockets = parse_listening_sockets(
        "tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\"))\nudp UNCONN 0 0 "
        "0.0.0.0:5353 0.0.0.0:* users:((\"avahi-daemon\"))\nudp UNCONN 0 0 239.255.255.250:3702 "
        "0.0.0.0:* users:((\"wsdd\"))\n");
    SocketState state;
    state.available = true;
    state.listeners = sockets;
    const auto exposure = summarize_listener_exposure(state);
    expect(sockets.size() == 3 && sockets.front().loopback_only && !sockets.at(1).loopback_only &&
               sockets.back().multicast_only && exposure.logical_network_services == 1 &&
               exposure.network_reachable_bindings == 1,
           "classifies listener exposure conservatively");
    expect(count_journal_entries("-- Boot --\nDROP packet\n-- No entries --\n") == 1 &&
               summarize_kernel_denials("DROP SRC=192.0.2.1 DPT=22\nREJECT SRC=192.0.2.2 DPT=443\n")
                       .unique_sources == 2,
           "summarizes firewall telemetry without retaining values");
    const auto route = parse_default_route("default via 192.0.2.1 dev wlp0s20f3 proto dhcp\n");
    expect(route.default_gateway == "192.0.2.1" && route.default_interface == "wlp0s20f3" &&
               is_valid_ip_address("2001:db8::1") && !is_valid_ip_address("bad"),
           "parses default-route metadata");

    const SequencedCommandRunner backend_runner(
        {{0, "1.0\n", {}},
         {0, "running\n", {}},
         {0, "enabled\n", {}},
         {1, "no\n", {}},
         {0, {}, {}},
         {0, "off\n", {}},
         {0, "public\n", {}},
         {0, "public\n  interfaces: enp1s0\n", {}},
         {0, "public\n target: default\n interfaces: enp1s0\n", {}},
         {0, "public\n target: default\n", {}},
         {0, "allow-host-ipv6\n", {}}});
    const FirewalldCommandBackend backend(backend_runner);
    const auto collected = backend.inspect(PostureCollectionDepth::Complete);
    expect(collected.installation_status == ObservationStatus::Available &&
               collected.panic_state == ObservationStatus::Available && !collected.panic &&
               collected.active_zones_status == ObservationStatus::Available &&
               collected.runtime_zones_status == ObservationStatus::Available &&
               collected.permanent_zones_status == ObservationStatus::Available &&
               collected.active_policies_status == ObservationStatus::Available,
           "tracks successful false firewall observations separately from unavailable evidence");

    const SequencedCommandRunner unavailable_runtime_runner(
        {{0, "1.0\n", {}},
         {0, "running\n", {}},
         {0, "enabled\n", {}},
         {1, "no\n", {}},
         {0, {}, {}},
         {0, "off\n", {}},
         {0, "public\n", {}},
         {0, "public\n  interfaces: enp1s0\n", {}},
         {-1, {}, "D-Bus unavailable"}});
    const FirewalldCommandBackend unavailable_runtime_backend(unavailable_runtime_runner);
    const auto unavailable_runtime =
        unavailable_runtime_backend.inspect(PostureCollectionDepth::Landing);
    bool exposure_unknown = false, target_unknown = false, drift_unknown = false;
    for (const auto &check : assess_readiness(unavailable_runtime)) {
        exposure_unknown =
            exposure_unknown || (check.label == "inbound services, ports, and protocols" &&
                                 check.level == CheckLevel::Warn);
        target_unknown = target_unknown ||
                         (check.label == "active zone target" && check.level == CheckLevel::Warn);
        drift_unknown = drift_unknown || (check.label == "permanent/runtime state aligned" &&
                                          check.level == CheckLevel::Warn);
    }
    expect(
        unavailable_runtime.runtime_zones_status == ObservationStatus::Unavailable &&
               !applicable_zone_details_available(unavailable_runtime) && exposure_unknown &&
            target_unknown && drift_unknown,
        "records failed runtime-zone collection as unavailable rather than an empty safe policy");

    const SequencedCommandRunner malformed_runner(
        {{0, "1.0\n", {}},
         {0, "running\n", {}},
         {0, "enabled\n", {}},
         {1, "no\n", {}},
         {0, {}, {}},
         {0, "not-a-log-setting\n", {}},
         {0, "public extra\n", {}},
         {0, "garbage\n", {}},
         {0, "garbage\n", {}}});
    const FirewalldCommandBackend malformed_backend(malformed_runner);
    const auto malformed = malformed_backend.inspect(PostureCollectionDepth::Landing);
    expect(malformed.denied_logging_status == ObservationStatus::Partial &&
               malformed.default_zone_status == ObservationStatus::Partial &&
               malformed.active_zones_status == ObservationStatus::Partial &&
               malformed.runtime_zones_status == ObservationStatus::Partial,
           "does not treat successful but malformed firewall output as usable evidence");
    const auto malformed_boolean =
        parse_zone_info("target: default\nmasquerade: perhaps\nforward: yes\n");
    expect(!malformed_boolean.details_valid,
           "marks malformed firewalld yes-or-no zone fields as invalid rather than disabled");
    const SequencedCommandRunner malformed_boolean_runner(
        {{0, "1.0\n", {}},
         {0, "running\n", {}},
         {0, "enabled\n", {}},
         {1, "no\n", {}},
         {0, {}, {}},
         {0, "off\n", {}},
         {0, "public\n", {}},
         {0, "public\n interfaces: enp1s0\n", {}},
         {0, "public\n target: default\n masquerade: perhaps\n", {}}});
    const FirewalldCommandBackend malformed_boolean_backend(malformed_boolean_runner);
    expect(malformed_boolean_backend.inspect(PostureCollectionDepth::Landing).runtime_zones_status ==
               ObservationStatus::Partial,
           "does not promote malformed zone Boolean fields to available runtime policy evidence");

    const SequencedCommandRunner failed_journal_runner(
        {{1, "-- No entries --\n", "permission denied"}, {0, "-- No entries --\n", {}}});
    const SecuritySignalsInspector failed_journals(failed_journal_runner);
    const auto failed_journal_state = failed_journals.inspect();
    expect(!failed_journal_state.kernel_journal_available &&
               failed_journal_state.kernel_journal_status == JournalQueryStatus::Unavailable &&
               failed_journal_state.firewalld_journal_available,
           "does not mistake an error response containing no-entries text for journal evidence");

    std::string bounded_kernel_output;
    for (unsigned int index = 0; index < 200U; ++index)
        bounded_kernel_output += "DROP SRC=192.0.2.1 DPT=22\n";
    const SequencedCommandRunner bounded_journal_runner(
        {{0, bounded_kernel_output, {}}, {0, bounded_kernel_output, {}}});
    const SecuritySignalsInspector bounded_journals(bounded_journal_runner);
    const auto bounded_journal_state = bounded_journals.inspect();
    expect(bounded_journal_state.kernel_journal_status == JournalQueryStatus::Partial &&
               bounded_journal_state.firewalld_journal_status == JournalQueryStatus::Partial &&
               bounded_journal_state.kernel_drop_or_reject_events == 200U,
           "marks journal results at the bounded limit as partial lower-bound evidence");
}
} // namespace ffc::test
