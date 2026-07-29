#include "test_support.hpp"

#include "ffc/firewall_state.hpp"
#include "ffc/readiness.hpp"
#include "ffc/threat_assessment.hpp"

namespace ffc::test {
void run_posture_threat_tests() {
    FirewallState state;
    state.installed = state.active = state.enabled = state.permanent_config_checked = state.permanent_config_valid = true;
    state.default_zone = "public";
    const auto zone = parse_zone_info("target: ACCEPT\ninterfaces: enp1s0\nservices: ssh\nmasquerade: yes\nforward: no\n");
    state.runtime_zones["public"] = zone; state.permanent_zones["public"] = zone; state.active_zone_interfaces["public"] = {"enp1s0"};
    bool masquerade_warning = false, accept_failure = false;
    for (const auto& check : assess_readiness(state)) { masquerade_warning = masquerade_warning || (check.label == "masquerading disabled" && check.level == CheckLevel::Warn); accept_failure = accept_failure || (check.label == "active zone target" && check.level == CheckLevel::Fail); }
    expect(masquerade_warning && accept_failure && ReadinessCheck{}.level == CheckLevel::Info, "reports readiness risks with safe defaults");
    state.log_denied = "off"; state.sockets.available = true; state.sockets.listeners = {{"tcp", "0.0.0.0:22", false, false, {}}}; state.security_signals.kernel_journal_available = true;
    state.permanent_zones["public"].target = "DROP"; state.runtime_zones["public"].ports = {"1025-65535/tcp"}; state.runtime_zones["public"].forward = true;
    const auto assessment = assess_threat_evidence(state);
    bool logging_gap = false, listener_exposure = false, drift_candidate = false, broad_range = false, forwarding_context = false;
    for (const auto& finding : assessment.findings) { logging_gap = logging_gap || (finding.kind == ThreatFindingKind::CoverageGap && finding.title == "Denied-packet logging is off"); listener_exposure = listener_exposure || (finding.kind == ThreatFindingKind::Exposure && finding.title == "Network-reachable local listeners"); drift_candidate = drift_candidate || (finding.kind == ThreatFindingKind::CandidateAlert && finding.title == "Firewall runtime/permanent drift"); broad_range = broad_range || (finding.kind == ThreatFindingKind::Exposure && finding.title == "Broad inbound port range configured"); forwarding_context = forwarding_context || (finding.kind == ThreatFindingKind::NoAlert && finding.title == "Intra-zone forwarding has no current path"); }
    expect(logging_gap && listener_exposure && drift_candidate && broad_range && forwarding_context && assessment.verdict_rules.size() == 4, "separates exposure evidence coverage gaps and unverified candidates");
    state.security_signals.kernel_drop_or_reject_events = 2; bool denial_candidate = false;
    const auto telemetry_assessment = assess_threat_evidence(state);
    for (const auto& finding : telemetry_assessment.findings) denial_candidate = denial_candidate || finding.title == "Denied-packet activity observed";
    expect(denial_candidate, "keeps observed denial telemetry visible when default logging is off");
}
} // namespace ffc::test
