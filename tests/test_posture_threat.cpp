#include "test_support.hpp"

#include "ffc/firewall_state.hpp"
#include "ffc/readiness.hpp"
#include "ffc/threat_assessment.hpp"

namespace ffc::test {
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
                                  finding.title == "Network-reachable local listeners");
        drift_candidate = drift_candidate || (finding.kind == ThreatFindingKind::CandidateAlert &&
                                              finding.title == "Firewall runtime/permanent drift");
        broad_range = broad_range || (finding.kind == ThreatFindingKind::Exposure &&
                                      finding.title == "Broad inbound port range configured");
        forwarding_context =
            forwarding_context || (finding.kind == ThreatFindingKind::NoAlert &&
                                   finding.title == "Intra-zone forwarding has no current path");
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
}
} // namespace ffc::test
