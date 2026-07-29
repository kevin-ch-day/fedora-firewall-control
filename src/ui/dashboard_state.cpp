#include "ffc/dashboard_state.hpp"

#include "ffc/readiness.hpp"

#include <algorithm>
#include <array>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <unistd.h>

namespace ffc {
namespace {

struct ActiveExposure {
    std::size_t ports{0};
    std::size_t protocols{0};
    std::size_t rich_rules{0};
    bool forwarding{false};
    bool masquerading{false};
    bool accept_target{false};
};

ActiveExposure active_exposure(const FirewallState& state) {
    ActiveExposure exposure;
    for (const auto& [zone_name, zone] : state.runtime_zones) {
        if (!is_zone_applicable(state, zone_name))
            continue;
        exposure.ports += zone.ports.size();
        exposure.protocols += zone.protocols.size();
        exposure.rich_rules += zone.rich_rules.size();
        exposure.forwarding = exposure.forwarding || zone.forward;
        exposure.masquerading = exposure.masquerading || zone.masquerade;
        exposure.accept_target = exposure.accept_target || zone.target == "ACCEPT";
    }
    return exposure;
}

void add_component(DashboardSnapshot& snapshot, std::string component,
                   const ObservationStatus status, std::string detail) {
    snapshot.evidence_components.push_back({std::move(component), status, std::move(detail)});
}

void add_gap(DashboardSnapshot& snapshot, std::string id, std::string summary,
             const MenuDestination destination) {
    snapshot.coverage_gaps.push_back(
        {FindingSeverity::Medium, FindingCategory::EvidenceGap, std::move(id), std::move(summary),
         destination});
}

void add_review(DashboardSnapshot& snapshot, std::string id, std::string summary,
                const FindingCategory category, const MenuDestination destination,
                const FindingSeverity severity = FindingSeverity::High) {
    snapshot.review_items.push_back(
        {severity, category, std::move(id), std::move(summary), destination});
}

void add_blocker(DashboardSnapshot& snapshot, std::string id, std::string summary,
                 const FindingCategory category) {
    snapshot.blockers.push_back({FindingSeverity::Critical, category, std::move(id),
                                 std::move(summary), MenuDestination::Readiness});
}

std::string local_hostname() {
    std::array<char, 256> buffer{};
    if (gethostname(buffer.data(), buffer.size() - 1U) != 0)
        return "unknown";
    return buffer.data();
}

int recommendation_priority(const DashboardRecommendation& recommendation) {
    switch (recommendation.category) {
    case FindingCategory::Isolation:
        return 800;
    case FindingCategory::Firewall:
        return 750;
    case FindingCategory::Exposure:
        return 700;
    case FindingCategory::Listener:
        return 600;
    case FindingCategory::Change:
        return 500;
    case FindingCategory::EvidenceGap:
        return 300;
    case FindingCategory::Hygiene:
        return 100;
    }
    return 0;
}

void add_recommendation(DashboardSnapshot& snapshot, const DashboardFinding& finding) {
    snapshot.recommendations.push_back(
        {finding.severity, finding.category, finding.id, finding.summary, finding.destination});
}

} // namespace

DashboardSnapshot make_dashboard_snapshot(FirewallState firewall, const std::uint64_t snapshot_id,
                                           const std::chrono::system_clock::time_point collected_at,
                                           const std::chrono::steady_clock::time_point collected_monotonic) {
    DashboardSnapshot snapshot;
    snapshot.snapshot_id = snapshot_id != 0U ? snapshot_id : static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(collected_at.time_since_epoch()).count());
    snapshot.collected_at = collected_at;
    snapshot.collected_monotonic = collected_monotonic;
    snapshot.hostname = local_hostname();
#ifdef FFC_APPLICATION_VERSION
    snapshot.application_version = FFC_APPLICATION_VERSION;
#else
    snapshot.application_version = "development";
#endif
    snapshot.firewall = std::move(firewall);
    const auto& state = snapshot.firewall;

    add_component(snapshot, "firewalld runtime policy", state.runtime_zones_status,
                  observation_available(state.runtime_zones_status) ? "collected" : "unavailable");
    add_component(snapshot, "firewalld permanent policy", state.permanent_zones_status,
                  observation_available(state.permanent_zones_status) ? "collected" : "unavailable");
    add_component(snapshot, "NetworkManager device inventory",
                  state.network_manager.available ? ObservationStatus::Available : ObservationStatus::Unavailable,
                  state.network_manager.available ? "collected" : state.network_manager.diagnostic);
    add_component(snapshot, "NetworkManager profile and autoconnect inventory",
                  ObservationStatus::Unavailable, "not collected by this read-only snapshot");
    add_component(snapshot, "TCP/UDP listener inventory",
                  state.sockets.available ? ObservationStatus::Available : ObservationStatus::Unavailable,
                  state.sockets.available ? "collected" : state.sockets.diagnostic);
    add_component(snapshot, "kernel denied-packet journal",
                  state.security_signals.kernel_journal_available ? ObservationStatus::Available
                                                                  : ObservationStatus::Unavailable,
                  state.security_signals.kernel_journal_available ? "collected"
                                                                   : state.security_signals.diagnostic);
    add_component(snapshot, "firewalld service journal",
                  state.security_signals.firewalld_journal_available ? ObservationStatus::Available
                                                                     : ObservationStatus::Unavailable,
                  state.security_signals.firewalld_journal_available ? "collected"
                                                                      : state.security_signals.diagnostic);
    add_component(snapshot, "VPN route, DNS, and kill-switch verification", ObservationStatus::Unavailable,
                  "not implemented in this read-only snapshot");

    for (const auto& component : snapshot.evidence_components)
        if (component.status != ObservationStatus::Available)
            add_gap(snapshot, "evidence." + component.component, component.component + " unavailable: " +
                        component.detail, component.component.starts_with("NetworkManager") ||
                                                   component.component.starts_with("VPN")
                                               ? MenuDestination::Network
                                               : MenuDestination::Evidence);

    if (!state.installed)
        add_blocker(snapshot, "firewalld.missing", "Install firewalld before evaluating host policy.",
                    FindingCategory::Firewall);
    else if (!observation_available(state.service_state))
        add_blocker(snapshot, "firewalld.state-unavailable", "Restore firewalld state collection before relying on posture.",
                    FindingCategory::Firewall);
    else if (!state.active)
        add_blocker(snapshot, "firewalld.inactive", "Start firewalld; current host policy is not being enforced.",
                    FindingCategory::Firewall);
    if (observation_available(state.panic_state) && state.panic)
        add_blocker(snapshot, "firewalld.panic", "Panic mode is active; all network traffic may be blocked.",
                    FindingCategory::Isolation);

    if (applicable_zone_details_available(state)) {
        const auto exposure = active_exposure(state);
        if (exposure.ports != 0U || exposure.protocols != 0U || exposure.rich_rules != 0U ||
            exposure.accept_target) {
            std::string summary = "Review active inbound policy:";
            if (exposure.ports != 0U)
                summary += " " + std::to_string(exposure.ports) + " port rule(s)";
            if (exposure.protocols != 0U)
                summary += (summary.ends_with(":") ? " " : ", ") +
                           std::to_string(exposure.protocols) + " protocol rule(s)";
            if (exposure.rich_rules != 0U)
                summary += (summary.ends_with(":") ? " " : ", ") +
                           std::to_string(exposure.rich_rules) + " rich rule(s)";
            if (exposure.accept_target) {
                summary += summary.ends_with(":") ? " " : ", ";
                summary += "an ACCEPT zone target";
            }
            if (exposure.forwarding) {
                summary += summary.ends_with(":") ? " " : ", ";
                summary += "intra-zone forwarding";
            }
            summary += ".";
            add_review(snapshot, "firewall.active-inbound-policy", std::move(summary),
                       FindingCategory::Exposure, MenuDestination::Firewall);
        }
        if (exposure.forwarding)
            add_review(snapshot, "firewall.intra-zone-forwarding",
                       "Review intra-zone forwarding; it is enabled on an applicable zone.",
                       FindingCategory::Exposure, MenuDestination::Firewall);
        if (exposure.masquerading)
            add_review(snapshot, "firewall.masquerading", "Review masquerading; it is enabled on an applicable zone.",
                       FindingCategory::Exposure, MenuDestination::Firewall);
    } else {
        add_gap(snapshot, "firewall.applicable-policy", "Applicable firewall policy detail is unavailable.",
                MenuDestination::Firewall);
    }

    if (state.sockets.available) {
        const auto listeners = summarize_listener_exposure(state.sockets);
        if (listeners.logical_network_services != 0U)
            add_review(snapshot, "listeners.network-reachable",
                       "Review " + std::to_string(listeners.logical_network_services) +
                           " network-reachable TCP/UDP listener(s).",
                       FindingCategory::Listener, MenuDestination::Firewall, FindingSeverity::Medium);
    }

    for (const auto& blocker : snapshot.blockers)
        add_recommendation(snapshot, blocker);
    for (const auto& review : snapshot.review_items)
        add_recommendation(snapshot, review);
    for (const auto& gap : snapshot.coverage_gaps)
        add_recommendation(snapshot, gap);
    std::stable_sort(snapshot.recommendations.begin(), snapshot.recommendations.end(),
                     [](const auto& left, const auto& right) {
                         return recommendation_priority(left) > recommendation_priority(right);
                     });

    snapshot.risk = !snapshot.blockers.empty() ? DashboardRisk::Blocked
                    : !snapshot.review_items.empty() ? DashboardRisk::Review
                                                     : DashboardRisk::Ready;
    if (state.operating_mode == OperatingMode::HostileNetwork) {
        snapshot.defcon_readiness = snapshot.blockers.empty() && snapshot.review_items.empty()
                                       ? DefconReadiness::Ready
                                       : DefconReadiness::NotReady;
    }
    bool any_partial = false;
    bool any_available = false;
    for (const auto& component : snapshot.evidence_components) {
        any_partial = any_partial || component.status != ObservationStatus::Available;
        any_available = any_available || component.status == ObservationStatus::Available;
    }
    snapshot.overall_evidence = !any_partial ? ObservationStatus::Available
                                : any_available ? ObservationStatus::Partial
                                                : ObservationStatus::Unavailable;
    return snapshot;
}

DashboardState make_dashboard_state(FirewallState firewall) {
    return make_dashboard_snapshot(std::move(firewall));
}

std::string_view to_string(const DashboardRisk risk) {
    switch (risk) {
    case DashboardRisk::Ready: return "READY FOR REVIEW";
    case DashboardRisk::Review: return "REVIEW REQUIRED";
    case DashboardRisk::Blocked: return "READINESS BLOCKED";
    }
    return "REVIEW REQUIRED";
}

std::string_view to_string(const DefconReadiness readiness) {
    switch (readiness) {
    case DefconReadiness::NotEvaluated: return "NOT EVALUATED";
    case DefconReadiness::Ready: return "READY";
    case DefconReadiness::NotReady: return "NOT READY";
    }
    return "NOT EVALUATED";
}

std::string_view to_string(const MenuDestination destination) {
    switch (destination) {
    case MenuDestination::Readiness: return "Readiness";
    case MenuDestination::Signals: return "Signals";
    case MenuDestination::Firewall: return "Firewall";
    case MenuDestination::Network: return "Network and VPN";
    case MenuDestination::Evidence: return "Evidence";
    case MenuDestination::Settings: return "Settings";
    case MenuDestination::Emergency: return "Emergency";
    }
    return "Readiness";
}

std::string format_dashboard_timestamp(const std::chrono::system_clock::time_point timestamp) {
    const auto time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm utc{};
    gmtime_r(&time, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%H:%M:%SZ");
    return output.str();
}

std::string format_dashboard_local_time(const std::chrono::system_clock::time_point timestamp) {
    const auto time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm local{};
    localtime_r(&time, &local);
    std::ostringstream output;
    output << std::put_time(&local, "%H:%M:%S %Z");
    return output.str();
}

std::string format_dashboard_age(const DashboardSnapshot& snapshot,
                                 const std::chrono::steady_clock::time_point now) {
    const auto elapsed = now > snapshot.collected_monotonic ? now - snapshot.collected_monotonic
                                                              : std::chrono::steady_clock::duration::zero();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    if (seconds >= 30)
        return "STALE • last successful update " + std::to_string(seconds) + "s ago";
    return std::to_string(seconds) + "s old";
}

} // namespace ffc
