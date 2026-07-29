#include "test_support.hpp"

#include "ffc/dashboard.hpp"
#include "ffc/dashboard_json.hpp"
#include "ffc/dashboard_state.hpp"
#include "ffc/firewall_state.hpp"
#include "ffc/readiness.hpp"
#include "ffc/terminal_ui.hpp"
#include "ffc/threat_assessment.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <sstream>

namespace ffc::test {
namespace {
class CoutRedirect final {
public:
    explicit CoutRedirect(std::ostream& target) : previous_(std::cout.rdbuf(target.rdbuf())) {}
    ~CoutRedirect() { std::cout.rdbuf(previous_); }

private:
    std::streambuf* previous_;
};
} // namespace

void run_posture_threat_tests() {
    FirewallState state;
    state.installed = state.active = state.enabled = state.permanent_config_checked =
        state.permanent_config_valid = true;
    state.service_state = state.service_enablement = state.panic_state = state.permanent_config =
        state.default_zone_status = state.denied_logging_status = state.active_zones_status =
            state.runtime_zones_status = state.permanent_zones_status =
                state.active_policies_status = ObservationStatus::Available;
    state.default_zone = "public";
    const auto zone = parse_zone_info(
        "target: ACCEPT\ninterfaces: enp1s0\nservices: ssh\nmasquerade: yes\nforward: no\n");
    state.runtime_zones["public"] = zone;
    state.permanent_zones["public"] = zone;
    state.active_zone_interfaces["public"] = {"enp1s0"};
    bool masquerade_warning = false, accept_failure = false;
    for (const auto &check : assess_readiness(state)) {
        masquerade_warning = masquerade_warning || (check.label == "masquerading disabled" &&
                                                    check.level == CheckLevel::Warn);
        accept_failure = accept_failure ||
                         (check.label == "active zone target" && check.level == CheckLevel::Fail);
    }
    expect(masquerade_warning && accept_failure && ReadinessCheck{}.level == CheckLevel::Info,
           "reports readiness risks with safe defaults");
    state.log_denied = "off";
    state.sockets.available = true;
    state.sockets.listeners = {{"tcp", "0.0.0.0:22", false, false, {}}};
    state.security_signals.kernel_journal_available = true;
    state.permanent_zones["public"].target = "DROP";
    state.runtime_zones["public"].ports = {"1025-65535/tcp"};
    state.runtime_zones["public"].forward = true;
    const auto assessment = assess_threat_evidence(state);
    bool logging_gap = false, listener_exposure = false, drift_candidate = false,
         broad_range = false, forwarding_context = false;
    for (const auto &finding : assessment.findings) {
        logging_gap = logging_gap || (finding.kind == ThreatFindingKind::CoverageGap &&
                                      finding.title == "Denied-packet logging is off");
        listener_exposure =
            listener_exposure || (finding.kind == ThreatFindingKind::Exposure &&
                                  finding.title == "TCP/UDP non-multicast local listeners");
        drift_candidate = drift_candidate || (finding.kind == ThreatFindingKind::CandidateAlert &&
                                              finding.title == "Firewall runtime/permanent drift");
        broad_range = broad_range || (finding.kind == ThreatFindingKind::Exposure &&
                                      finding.title == "Broad inbound port range configured");
        forwarding_context =
            forwarding_context || (finding.kind == ThreatFindingKind::ScopeLimit &&
                                   finding.title == "Intra-zone forwarding topology not established");
    }
    expect(logging_gap && listener_exposure && drift_candidate && broad_range &&
               forwarding_context && assessment.verdict_rules.size() == 4,
           "separates exposure evidence coverage gaps and unverified candidates");
    state.security_signals.kernel_drop_or_reject_events = 2;
    bool denial_candidate = false;
    const auto telemetry_assessment = assess_threat_evidence(state);
    for (const auto &finding : telemetry_assessment.findings)
        denial_candidate = denial_candidate || finding.title == "Denied-packet activity observed";
    expect(denial_candidate, "keeps observed denial telemetry visible when default logging is off");

    FirewallState source_only = state;
    source_only.runtime_zones.clear();
    source_only.permanent_zones.clear();
    source_only.active_zone_interfaces.clear();
    const auto source_zone = parse_zone_info(
        "target: ACCEPT\nsources: 198.51.100.0/24\nservices: ssh\nports: 1025-65535/tcp\n"
        "protocols: esp\nsource-ports: 1024-65535\nforward-ports: port=8080:proto=tcp:toport=80\n"
        "masquerade: yes\nforward: yes\n");
    source_only.runtime_zones["trusted"] = source_zone;
    source_only.permanent_zones["trusted"] = source_zone;
    source_only.active_zone_sources["trusted"] = {"198.51.100.0/24"};
    source_only.network_manager.available = true;
    bool source_target = false, source_exposure = false, source_masquerade = false,
         source_forward_ports = false, source_forwarding_evaluated = false;
    for (const auto &check : assess_readiness(source_only)) {
        source_target = source_target ||
                        (check.label == "active zone target" && check.level == CheckLevel::Fail);
        source_exposure =
            source_exposure || (check.label == "inbound services, ports, and protocols" &&
                                check.level == CheckLevel::Warn);
        source_masquerade = source_masquerade || (check.label == "masquerading disabled" &&
                                                  check.level == CheckLevel::Warn);
        source_forward_ports = source_forward_ports || (check.label == "active forward ports" &&
                                                        check.level == CheckLevel::Warn);
        source_forwarding_evaluated =
            source_forwarding_evaluated ||
            (check.label == "intra-zone forwarding" && check.level == CheckLevel::Info);
    }
    const auto source_assessment = assess_threat_evidence(source_only);
    bool source_broad_range = false, source_selector_exposure = false;
    for (const auto &finding : source_assessment.findings) {
        source_broad_range =
            source_broad_range || (finding.title == "Broad inbound port range configured");
        source_selector_exposure = source_selector_exposure ||
                                   (finding.title == "Active-zone protocol or source-port rules");
    }
    expect(source_target && source_exposure && source_masquerade && source_forward_ports &&
               source_forwarding_evaluated && source_broad_range && source_selector_exposure &&
               source_zone.protocols == std::vector<std::string>{"esp"} &&
               source_zone.source_ports == std::vector<std::string>{"1024-65535"},
           "assesses source-only active zones as active policy exposure");

    FirewallState permanent_only = source_only;
    permanent_only.permanent_zones["home"] = parse_zone_info("target: DROP\n");
    const auto permanent_only_assessment = assess_threat_evidence(permanent_only);
    bool permanent_only_drift = false;
    for (const auto &finding : permanent_only_assessment.findings)
        permanent_only_drift =
            permanent_only_drift || (finding.title == "Firewall runtime/permanent drift");
    expect(permanent_only_drift, "detects permanent-only firewall policy drift");

    FirewallState unavailable;
    unavailable.installed = unavailable.active = true;
    bool panic_unknown = false, exposure_unknown = false, drift_unknown = false;
    for (const auto &check : assess_readiness(unavailable)) {
        panic_unknown = panic_unknown ||
                        (check.label == "firewalld panic mode" && check.level == CheckLevel::Warn);
        exposure_unknown =
            exposure_unknown || (check.label == "inbound services, ports, and protocols" &&
                                 check.level == CheckLevel::Warn);
        drift_unknown = drift_unknown || (check.label == "permanent/runtime state aligned" &&
                                          check.level == CheckLevel::Warn);
    }
    expect(panic_unknown && exposure_unknown && drift_unknown,
           "does not report unavailable firewall evidence as a safe state");

    FirewallState partial = state;
    partial.active_policies_status = ObservationStatus::Partial;
    bool partial_policy_warning = false;
    for (const auto &check : assess_readiness(partial))
        partial_policy_warning =
            partial_policy_warning ||
            (check.label == "active firewalld policies" && check.level == CheckLevel::Warn);
    expect(partial_policy_warning,
           "does not treat partially collected policy evidence as a clean policy inventory");

    FirewallState default_fallback = state;
    default_fallback.active_zone_interfaces.clear();
    default_fallback.active_zone_sources.clear();
    default_fallback.network_manager.available = true;
    default_fallback.network_manager.devices = {{"enp99s0", "ethernet", "connected"}};
    default_fallback.runtime_zones["public"] = parse_zone_info(
        "target: default\nservices: ssh\nports: 8443/tcp\nprotocols: esp\nsource-ports: "
        "1024-65535\n rule family=\"ipv4\" service name=\"ssh\" accept\n");
    default_fallback.permanent_zones["public"] = default_fallback.runtime_zones["public"];
    bool default_exposure = false, default_rich_rules = false;
    for (const auto& check : assess_readiness(default_fallback)) {
        default_exposure = default_exposure ||
                           (check.label == "inbound services, ports, and protocols" &&
                            check.level == CheckLevel::Warn);
        default_rich_rules = default_rich_rules ||
                             (check.label == "active rich rules" && check.level == CheckLevel::Warn);
    }
    bool default_rich_finding = false;
    const auto default_assessment = assess_threat_evidence(default_fallback);
    for (const auto& finding : default_assessment.findings)
        default_rich_finding = default_rich_finding ||
                               (finding.title == "Applicable-zone rich rules" &&
                                finding.kind == ThreatFindingKind::Exposure);
    expect(is_zone_applicable(default_fallback, "public") && default_exposure &&
               default_rich_rules && default_rich_finding,
           "assesses default-zone exposure for a connected interface without an explicit binding");
    expect(!is_connected_transport_device({"lo", "loopback", "connected"}) &&
               !is_connected_transport_device({"nordlynx", "wireguard", "connected (externally)"}) &&
               is_connected_transport_device({"enp99s0", "ethernet", "connected"}),
           "keeps loopback and tunnel devices out of physical-transport zone fallback warnings");

    FirewallState multicast_only = state;
    multicast_only.sockets.available = true;
    multicast_only.sockets.listeners = {{"udp", "239.255.255.250:3702", false, true, "wsdd"}};
    bool normal_multicast_info = false;
    for (const auto& check : assess_readiness(multicast_only))
        normal_multicast_info = normal_multicast_info ||
                                (check.label == "multicast listener exposure" &&
                                 check.level == CheckLevel::Info);
    multicast_only.operating_mode = OperatingMode::HostileNetwork;
    bool hostile_multicast_warning = false;
    for (const auto& check : assess_readiness(multicast_only))
        hostile_multicast_warning = hostile_multicast_warning ||
                                   (check.label == "multicast listener exposure" &&
                                    check.level == CheckLevel::Warn);
    expect(normal_multicast_info && hostile_multicast_warning,
           "keeps multicast listener traffic visible and raises it for hostile-network review");

    FirewallState dashboard_source;
    dashboard_source.installed = dashboard_source.active = dashboard_source.enabled =
        dashboard_source.permanent_config_checked = dashboard_source.permanent_config_valid = true;
    dashboard_source.service_state = dashboard_source.service_enablement = dashboard_source.panic_state =
        dashboard_source.permanent_config = dashboard_source.default_zone_status =
            dashboard_source.denied_logging_status = dashboard_source.active_zones_status =
                dashboard_source.runtime_zones_status = dashboard_source.permanent_zones_status =
                    dashboard_source.active_policies_status = ObservationStatus::Available;
    dashboard_source.default_zone = "public";
    dashboard_source.log_denied = "all";
    dashboard_source.runtime_zones["public"] = parse_zone_info(
        "target: DROP\ninterfaces: enp1s0\nmasquerade: no\nforward: no\n");
    dashboard_source.permanent_zones = dashboard_source.runtime_zones;
    dashboard_source.active_zone_interfaces["public"] = {"enp1s0"};
    dashboard_source.network_manager.available = true;
    dashboard_source.vpn.interface_scan_available = true;
    dashboard_source.sockets.available = true;
    dashboard_source.security_signals.kernel_journal_available = true;
    dashboard_source.security_signals.firewalld_journal_available = true;
    const auto dashboard_state = make_dashboard_snapshot(dashboard_source, 42U);
    expect(dashboard_state.risk == DashboardRisk::Ready &&
               dashboard_state.defcon_readiness == DefconReadiness::NotEvaluated &&
               dashboard_state.overall_evidence == ObservationStatus::Partial &&
               !dashboard_state.coverage_gaps.empty(),
           "builds a shared dashboard snapshot with separate normal-mode DEF CON readiness and collector evidence");

    FirewallState prioritized = dashboard_source;
    prioritized.network_manager.available = false;
    prioritized.network_manager.diagnostic = "nmcli device status failed";
    prioritized.runtime_zones["public"].ports = {"443/tcp", "8443/tcp"};
    prioritized.runtime_zones["public"].forward = true;
    const auto prioritized_snapshot = make_dashboard_snapshot(prioritized);
    expect(!prioritized_snapshot.recommendations.empty() &&
               prioritized_snapshot.recommendations.front().category == FindingCategory::Exposure &&
               prioritized_snapshot.recommendations.front().destination == MenuDestination::Firewall &&
               prioritized_snapshot.recommendations.front().summary.find("port rule") != std::string::npos &&
               prioritized_snapshot.recommendations.front().summary.find("forwarding") != std::string::npos,
           "prioritizes active exposure over an unavailable NetworkManager collector");
    const auto network_manager_gap = std::find_if(
        prioritized_snapshot.coverage_gaps.begin(), prioritized_snapshot.coverage_gaps.end(),
        [](const DashboardFinding& gap) { return gap.id == "evidence.NetworkManager device inventory"; });
    expect(network_manager_gap != prioritized_snapshot.coverage_gaps.end() &&
               network_manager_gap->destination == MenuDestination::Network &&
               network_manager_gap->summary.find("nmcli device status failed") != std::string::npos,
           "keeps a named NetworkManager collection failure as a network coverage gap");

    FirewallState hostile = dashboard_source;
    hostile.operating_mode = OperatingMode::HostileNetwork;
    hostile.runtime_zones["public"].ports = {"443/tcp"};
    const auto hostile_snapshot = make_dashboard_snapshot(hostile);
    expect(hostile_snapshot.defcon_readiness == DefconReadiness::NotReady &&
               hostile_snapshot.risk == DashboardRisk::Review,
           "labels hostile-criteria DEF CON readiness separately from the current posture risk");

    const auto fixed_system_time = std::chrono::system_clock::time_point{std::chrono::seconds{1000}};
    const auto fixed_monotonic_time = std::chrono::steady_clock::time_point{std::chrono::seconds{1000}};
    const auto aged_snapshot = make_dashboard_snapshot(dashboard_source, 99U, fixed_system_time,
                                                        fixed_monotonic_time);
    expect(format_dashboard_age(aged_snapshot, fixed_monotonic_time + std::chrono::seconds{2}) == "2s old" &&
               format_dashboard_age(aged_snapshot, fixed_monotonic_time + std::chrono::seconds{47}).starts_with("STALE") &&
               to_string(MenuDestination::Firewall) == "Firewall",
           "models snapshot freshness and recommendation destinations independently of rendering");

    TerminalUi terminal;
    OperationsDashboard console(terminal);
    std::ostringstream output;
    {
        CoutRedirect redirect(output);
        console.show_menu(dashboard_state, DashboardMenu::Main);
        console.show_menu(dashboard_state, DashboardMenu::Main, true);
        console.show_detail_header(DashboardMenu::Firewall, "Firewall service state");
    }
    expect(output.str().find("DEF CON HOST DEFENSE") != std::string::npos &&
               output.str().find("Emergency isolation") != std::string::npos &&
               output.str().find("MAIN > Firewall and connections > Firewall service state") != std::string::npos &&
               output.str().find("Physical interface") != std::string::npos &&
               output.str().find("VPN route") != std::string::npos &&
               output.str().find("->") == std::string::npos && output.str().find("\033[") == std::string::npos,
           "renders workflow navigation without implying VPN routing or relying on color for severity meaning");
    expect(output.str().find("[ ? ] More") != std::string::npos &&
               output.str().find("Operational status") != std::string::npos &&
               output.str().find("Blockers, coverage gaps") == std::string::npos,
           "uses a compact default home, an explicit expanded view, and a short default menu");

    const auto json = serialize_dashboard_snapshot_json(prioritized_snapshot);
    expect(json.find("\"schema\": \"ffc.dashboard.v1\"") != std::string::npos &&
               json.find("\"snapshot_id\"") != std::string::npos &&
               json.find("\"intra_zone_forwarding\": true") != std::string::npos &&
               json.find("\"recommendation\"") != std::string::npos,
           "serializes the same structured dashboard snapshot as a versioned JSON contract");
    const auto unavailable_json = serialize_dashboard_snapshot_json(make_dashboard_snapshot({}));
    expect(unavailable_json.find("\"active_status\": \"unavailable\", \"active\": null") !=
                   std::string::npos &&
               unavailable_json.find("\"uses_tunnel\": null") != std::string::npos &&
               unavailable_json.find("\"status\": \"unavailable\"") != std::string::npos,
           "keeps unavailable firewall and VPN observations distinct from observed false values in JSON");

    FirewallState untrusted_network_manager = dashboard_source;
    untrusted_network_manager.network_manager.available = false;
    untrusted_network_manager.network_manager.diagnostic = "bad\x1b[2Jprofile";
    const auto untrusted_snapshot = make_dashboard_snapshot(untrusted_network_manager);
    std::ostringstream untrusted_output;
    {
        CoutRedirect redirect(untrusted_output);
        console.show_menu(untrusted_snapshot, DashboardMenu::Main, true);
    }
    expect(untrusted_output.str().find("\\x1B[2J") != std::string::npos &&
               untrusted_output.str().find("\x1b[2J") == std::string::npos,
           "sanitizes untrusted NetworkManager diagnostics at the dashboard display boundary");
}
} // namespace ffc::test
