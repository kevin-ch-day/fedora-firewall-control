#include "ffc/threat_assessment.hpp"

#include "ffc/port_intelligence.hpp"

#include <algorithm>

namespace ffc {
namespace {
std::size_t network_listener_count(const FirewallState &state) {
    return summarize_listener_exposure(state.sockets).logical_network_services;
}

std::size_t attributed_network_listener_count(const FirewallState &state) {
    return summarize_listener_exposure(state.sockets).process_attributed_network_bindings;
}

bool runtime_differs_from_permanent(const FirewallState &state) {
    if (!observation_available(state.runtime_zones_status) ||
        !observation_available(state.permanent_zones_status) ||
        state.runtime_zones.size() != state.permanent_zones.size())
        return true;
    return std::any_of(state.runtime_zones.begin(), state.runtime_zones.end(),
                       [&state](const auto &zone) {
                           const auto permanent = state.permanent_zones.find(zone.first);
                           return permanent == state.permanent_zones.end() ||
                                  !zone_policies_equal(zone.second, permanent->second);
                       });
}

std::vector<std::string> broad_active_port_ranges(const FirewallState &state) {
    std::vector<std::string> ranges;
    for (const auto &[zone_name, zone] : state.runtime_zones) {
        if (!is_zone_applicable(state, zone_name))
            continue;
        for (const auto &port_spec : zone.ports) {
            const auto intel = identify_port_spec(port_spec);
            if (!intel.port || !intel.range_end ||
                static_cast<unsigned int>(*intel.range_end) - *intel.port < 1024U)
                continue;
            ranges.push_back(zone_name + ": " + port_spec);
        }
    }
    return ranges;
}

bool active_zone_forwarding_enabled(const FirewallState &state) {
    return std::any_of(state.runtime_zones.begin(), state.runtime_zones.end(),
                       [&state](const auto &zone) {
                           return is_zone_applicable(state, zone.first) && zone.second.forward;
                       });
}

bool active_zone_forwarding_has_path(const FirewallState &state) {
    for (const auto &[zone_name, zone] : state.runtime_zones) {
        if (!is_zone_applicable(state, zone_name) || !zone.forward)
            continue;
        if (active_zone_member_count(state, zone_name) > 1U)
            return true;
    }
    return false;
}

std::string joined(const std::vector<std::string> &items) {
    std::string result;
    for (const auto &item : items)
        result += (result.empty() ? "" : ", ") + item;
    return result;
}

std::vector<std::string> active_protocol_or_source_port_rules(const FirewallState &state) {
    std::vector<std::string> rules;
    if (!applicable_zone_details_available(state))
        return rules;
    for (const auto &[zone_name, zone] : state.runtime_zones) {
        if (!is_zone_applicable(state, zone_name))
            continue;
        if (!zone.protocols.empty())
            rules.push_back(zone_name + " protocol=" + joined(zone.protocols));
        if (!zone.source_ports.empty())
            rules.push_back(zone_name + " source-port=" + joined(zone.source_ports));
    }
    return rules;
}

std::size_t applicable_rich_rule_count(const FirewallState &state) {
    if (!applicable_zone_details_available(state))
        return 0;
    std::size_t count = 0;
    for (const auto &[zone_name, zone] : state.runtime_zones)
        if (is_zone_applicable(state, zone_name))
            count += zone.rich_rules.size();
    return count;
}
} // namespace

std::string to_string(const ThreatFindingKind kind) {
    switch (kind) {
    case ThreatFindingKind::CandidateAlert:
        return "CANDIDATE ALERT";
    case ThreatFindingKind::Exposure:
        return "EXPOSURE";
    case ThreatFindingKind::CoverageGap:
        return "COVERAGE GAP";
    case ThreatFindingKind::ScopeLimit:
        return "SCOPE LIMIT";
    case ThreatFindingKind::NoAlert:
        return "NO ALERT";
    }
    return "UNKNOWN";
}

ThreatAssessment assess_threat_evidence(const FirewallState &state) {
    ThreatAssessment assessment;
    assessment.verdict_rules = {
        "True positive: a candidate alert corroborated as malicious by independent evidence.",
        "False positive: a candidate alert explained by expected or benign activity.",
        "True negative: no alert plus independent evidence that no relevant incident occurred.",
        "False negative: no alert followed by later confirmation of a relevant incident.",
    };

    if (!state.installed) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "firewall-cmd unavailable",
             "The firewalld command interface could not be queried.",
             "A missing firewall view can hide both permissive and restrictive policy.",
             "Restore firewalld tooling, then collect a fresh posture snapshot."});
    } else if (!state.active) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "firewalld runtime policy unavailable",
             "The firewall service was not confirmed running.",
             "A dashboard cannot infer active filtering policy while the service state is "
             "unavailable or inactive.",
             "Verify firewalld service state and its intended host firewall policy."});
    }
    if (!observation_available(state.active_zones_status)) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Active-zone collection unavailable",
             "The active firewalld zone query did not return a usable result.",
             "Interface and source bindings can change which policy applies to traffic.",
             "Restore firewall query access and compare active zones with NetworkManager."});
    }
    if (!observation_available(state.runtime_zones_status)) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Runtime-zone collection unavailable",
             "Runtime firewalld zone policy was not collected.",
             "A quiet exposure summary can be a false negative without runtime policy evidence.",
             "Restore firewall query access before drawing firewall exposure conclusions."});
    }
    if (!observation_available(state.permanent_zones_status)) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Permanent-zone collection unavailable",
             "Permanent firewalld zone policy was not collected.",
             "Drift cannot be assessed without both runtime and permanent policy views.",
             "Run a complete posture collection after restoring firewall query access."});
    }
    if (!observation_available(state.active_policies_status)) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Active policy inventory unavailable",
             "Active firewalld policy names were not collected.",
             "Policies can create host-bound or forwarding exposure outside zone settings.",
             "Collect policy inventory and inspect policy details before relying on readiness."});
    } else if (!state.active_policies.empty()) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Active policy details not assessed",
             std::to_string(state.active_policies.size()) +
                 " active firewalld policy name(s) were found.",
             "A named policy can allow services, ports, forwarding, or masquerading without "
             "proving hostile activity.",
             "Inspect each policy's ingress, egress, target, services, ports, and rich rules."});
    }
    if (!observation_available(state.panic_state)) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Panic-mode state unavailable",
             "The panic-mode query did not return a usable result.",
             "An unavailable query must not be interpreted as panic mode being off.",
             "Restore firewall query access and verify the state directly."});
    }

    if (state.security_signals.kernel_journal_status == JournalQueryStatus::Partial) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Kernel denial telemetry truncated",
             "At least " + std::to_string(state.security_signals.kernel_drop_or_reject_events) +
                 " retained event(s) reached the bounded journal query limit.",
             "Additional events may be absent from this view, so an apparent count or source mix is "
             "not complete.",
             "Collect a narrower time window or export retained journal evidence before drawing "
             "conclusions."});
    } else if (!state.security_signals.kernel_journal_available) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Kernel denial telemetry unavailable",
             "The journal query did not return a usable retained view.",
             "A quiet dashboard can be a false negative when this telemetry source is unavailable.",
             "Restore journal access, then compare firewall logs with host and network "
             "telemetry."});
    } else if (state.security_signals.kernel_drop_or_reject_events > 0) {
        const auto events = state.security_signals.kernel_drop_or_reject_events;
        const auto sources = state.security_signals.kernel_denial_unique_sources;
        const auto ports = state.security_signals.kernel_denial_unique_destination_ports;
        assessment.findings.push_back(
            {ThreatFindingKind::CandidateAlert, "Denied-packet activity observed",
             std::to_string(events) + " retained event(s); " + std::to_string(sources) +
                 " distinct source value(s); " + std::to_string(ports) +
                 " destination port value(s).",
             "Blocked scans, multicast discovery, return traffic, and local misconfiguration can "
             "all be false positives for hostile activity.",
             "Correlate timestamps, source/destination tuples, owning process, and packet capture "
             "before calling this a true positive."});
    } else if (!observation_available(state.denied_logging_status)) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Denied-packet logging state unavailable",
             "The firewall did not return a usable LogDenied setting.",
             "No retained deny events cannot be interpreted without knowing whether the firewall "
             "was configured to log them.",
             "Restore firewall query access and collect a new denial-telemetry window."});
    } else if (state.log_denied == "off") {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Denied-packet logging is off",
             "The firewall reports LogDenied=off, so denied-traffic counts are incomplete by "
             "design.",
             "No denied events is not a true negative while packet-denial logging is disabled; "
             "separately logged events remain candidates to investigate.",
             "Use a reviewed, rate-limited firewalld log, NFLOG, or audit rule for the traffic "
             "under investigation."});
    } else {
        assessment.findings.push_back(
            {ThreatFindingKind::NoAlert, "No retained kernel deny/reject events",
             "No matching events were found in the bounded 24-hour journal view.",
             "Normal background noise, logging gaps, and evasion can all produce no alert.",
             "Do not classify this as a true negative without independent host, network, and "
             "time-window evidence."});
    }

    if (!state.sockets.available) {
        assessment.findings.push_back({ThreatFindingKind::CoverageGap,
                                       "Listener inventory unavailable",
                                       "The local socket query failed or was unavailable.",
                                       "A missing inventory can hide a network-reachable service "
                                       "and create a false-negative exposure assessment.",
                                       "Restore socket visibility and validate listeners with "
                                       "their owning process and active-zone rules."});
    } else if (const auto listeners = network_listener_count(state); listeners > 0) {
        const auto attributed = attributed_network_listener_count(state);
        const auto exposure = summarize_listener_exposure(state.sockets);
        assessment.findings.push_back(
            {ThreatFindingKind::Exposure, "TCP/UDP non-multicast local listeners",
             std::to_string(listeners) + " logical TCP/UDP protocol/port service(s) across " +
                 std::to_string(exposure.network_reachable_bindings) +
                 " non-multicast binding(s); " + std::to_string(attributed) +
                 " binding(s) have a locally reported process name.",
             "A listening socket is not evidence of compromise; it may be an expected service, "
             "discovery responder, or VPN component.",
             "Verify owner, intended interface, firewall reachability, authentication, and whether "
             "the service is needed on this network."});
        if (attributed < exposure.network_reachable_bindings)
            assessment.findings.push_back(
                {ThreatFindingKind::CoverageGap, "Listener process attribution is incomplete",
                 std::to_string(exposure.network_reachable_bindings - attributed) +
                     " non-multicast network binding(s) had no process name in the local `ss` "
                     "view.",
                 "Missing process metadata can prevent benign attribution or hide a suspicious "
                 "owner, creating false-positive and false-negative risk.",
                 "Re-run with the necessary local privileges and compare with service-manager and "
                 "process telemetry."});
    } else {
        assessment.findings.push_back(
            {ThreatFindingKind::NoAlert, "No TCP/UDP non-multicast listeners observed",
             "The current socket snapshot found no TCP/UDP listener beyond loopback or multicast.",
             "This is a point-in-time observation, not proof that no service can appear later or "
             "that outbound abuse is absent.",
             "Refresh after network changes and combine with process and egress monitoring when "
             "needed."});
    }

    if (!state.evidence_quality.time_sync_status_available) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Time synchronization status unavailable",
             "The host could not report whether NTP synchronization is active.",
             "Unreliable timestamps make correlation harder and can cause events to be "
             "misattributed or missed across sources.",
             "Restore access to time status and verify the host clock before correlating local and "
             "network evidence."});
    } else if (!state.evidence_quality.time_synchronized) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "Host time is not synchronized",
             "The operating system reports that NTP synchronization is not established.",
             "Cross-source event timelines can be wrong when clocks diverge, weakening both "
             "positive and negative conclusions.",
             "Restore approved time synchronization, then record a fresh assessment window."});
    }
    if (!state.evidence_quality.journald_service_available)
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "systemd-journald is not active",
             "The local journal service was not reported active.",
             "Event retention and correlation may be incomplete, producing false-negative risk.",
             "Restore journald according to the host's approved logging policy before relying on "
             "journal-based findings."});

    assessment.findings.push_back(
        {ThreatFindingKind::ScopeLimit, "Outbound discovery behavior is outside this snapshot",
         "This console snapshots local listeners and bounded logs; it does not retain process "
         "execution, connection-flow, or packet-capture telemetry over time.",
         "A quiet listener or denial view cannot rule out outbound or lateral service discovery, "
         "including port scanning.",
         "Where authorized, correlate process execution with connection/flow telemetry or packet "
         "capture in a defined time window."});

    if (const auto broad_ranges = broad_active_port_ranges(state); !broad_ranges.empty()) {
        assessment.findings.push_back(
            {ThreatFindingKind::Exposure, "Broad inbound port range configured",
             "Active-zone range(s): " + joined(broad_ranges) +
                 ". This policy can permit many services if they bind beyond loopback.",
             "A broad range can be intentional for a lab, game, or temporary workflow; it does not "
             "prove any of those ports have a listening process today.",
             "Confirm the business need, scope it to the smallest required ports and interfaces, "
             "and review it as a deliberate firewall change."});
    }
    if (const auto selectors = active_protocol_or_source_port_rules(state); !selectors.empty()) {
        assessment.findings.push_back(
            {ThreatFindingKind::Exposure, "Active-zone protocol or source-port rules",
             "Active-zone selector(s): " + joined(selectors) + ".",
             "Protocol and source-port selectors can be deliberate policy constraints; they do "
             "not prove that a matching service is listening or that traffic is hostile.",
             "Review the matching zone target, services, ports, rich rules, and intended traffic "
             "direction."});
    }
    if (const auto rich_rules = applicable_rich_rule_count(state); rich_rules > 0) {
        assessment.findings.push_back(
            {ThreatFindingKind::Exposure, "Applicable-zone rich rules",
             std::to_string(rich_rules) +
                 " rich rule(s) are configured in zones applicable to current or fallback traffic.",
             "A rich rule can restrict, log, forward, reject, drop, or permit traffic; a count alone "
             "does not establish which effect applies to a specific flow.",
             "Review each rule's action, family, source, destination, service, port, protocol, and "
             "priority before relying on a clean exposure conclusion."});
    }
    if (active_zone_forwarding_enabled(state)) {
        if (active_zone_forwarding_has_path(state)) {
            assessment.findings.push_back(
                {ThreatFindingKind::Exposure, "Intra-zone forwarding has an active path",
                 "At least one active firewalld zone permits forwarding between multiple "
                 "interfaces or sources assigned to that same zone.",
                 "This can be a legitimate multi-interface, virtual-machine, or container "
                 "arrangement; it does not by itself prove IP routing or unauthorized transit.",
                 "Verify which interfaces and sources share the zone, and whether they are "
                 "intended to communicate through this host."});
        } else {
            assessment.findings.push_back(
                {ThreatFindingKind::ScopeLimit, "Intra-zone forwarding topology not established",
                 "Forwarding is configured, but the collected bindings did not establish a "
                 "multi-member interface/source pair.",
                 "Selector count is not verified route topology; a source selector can represent "
                 "multiple hosts and routing may change outside this snapshot.",
                 "Verify routes, interface membership, and intended same-zone traffic before "
                 "treating forwarding as inactive."});
        }
    }

    if (observation_available(state.runtime_zones_status) &&
        observation_available(state.permanent_zones_status) &&
        runtime_differs_from_permanent(state)) {
        assessment.findings.push_back(
            {ThreatFindingKind::CandidateAlert, "Firewall runtime/permanent drift",
             "At least one runtime zone differs from its permanent configuration.",
             "An administrator may have made a legitimate temporary change; drift alone is not "
             "malicious.",
             "Review the change timestamp, author, firewalld journal, and intended change record "
             "before classifying it."});
    }

    if (state.security_signals.firewalld_journal_status == JournalQueryStatus::Partial) {
        assessment.findings.push_back(
            {ThreatFindingKind::CoverageGap, "firewalld journal telemetry truncated",
             "At least " + std::to_string(state.security_signals.firewalld_service_events) +
                 " service event(s) reached the bounded journal query limit.",
             "The returned event count is a lower bound and is not a complete activity history.",
             "Inspect a narrower time window when investigating a candidate finding."});
    } else if (state.security_signals.firewalld_journal_available &&
        state.security_signals.firewalld_service_events > 0) {
        assessment.findings.push_back(
            {ThreatFindingKind::NoAlert, "Routine firewalld journal activity retained",
             std::to_string(state.security_signals.firewalld_service_events) +
                 " service journal event(s) in the bounded view; this count alone is not a threat "
                 "signal.",
             "Starts, reloads, package updates, and network changes commonly produce these "
             "entries.",
             "Use the timestamp and event content only when investigating a separate candidate "
             "finding."});
    }
    return assessment;
}
} // namespace ffc
