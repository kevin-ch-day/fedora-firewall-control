#pragma once

#include "ffc/firewall_state.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ffc {

// Transport-neutral dashboard data. Rendering layers add presentation and
// input handling; collectors never embed terminal control sequences here.
enum class DashboardRisk { Ready, Review, Blocked };
enum class DefconReadiness { NotEvaluated, Ready, NotReady };
enum class FindingSeverity { Critical, High, Medium, Low, Information };
enum class FindingCategory { Isolation, Firewall, Exposure, Listener, Change, EvidenceGap, Hygiene };
enum class MenuDestination { Readiness, Signals, Firewall, Network, Evidence, Settings, Emergency };

struct DashboardFinding {
    FindingSeverity severity{FindingSeverity::Information};
    FindingCategory category{FindingCategory::Hygiene};
    std::string id;
    std::string summary;
    MenuDestination destination{MenuDestination::Readiness};
};

struct DashboardRecommendation {
    FindingSeverity severity{FindingSeverity::Information};
    FindingCategory category{FindingCategory::Hygiene};
    std::string finding_id;
    std::string summary;
    MenuDestination destination{MenuDestination::Readiness};
};

struct ComponentEvidence {
    std::string component;
    ObservationStatus status{ObservationStatus::Unavailable};
    std::string detail;
};

struct DashboardSnapshot {
    static constexpr std::uint64_t schema_version{1};

    std::uint64_t snapshot_id{0};
    std::chrono::system_clock::time_point collected_at{};
    std::chrono::steady_clock::time_point collected_monotonic{};
    std::string hostname;
    std::string application_version;
    FirewallState firewall;
    DashboardRisk risk{DashboardRisk::Review};
    DefconReadiness defcon_readiness{DefconReadiness::NotEvaluated};
    ObservationStatus overall_evidence{ObservationStatus::Partial};
    std::vector<DashboardFinding> blockers;
    std::vector<DashboardFinding> review_items;
    std::vector<DashboardFinding> coverage_gaps;
    std::vector<DashboardRecommendation> recommendations;
    std::vector<ComponentEvidence> evidence_components;
    bool continuous_monitor_available{false};
    bool response_actions_available{false};
};

using DashboardState = DashboardSnapshot;

[[nodiscard]] DashboardSnapshot make_dashboard_snapshot(
    FirewallState firewall, std::uint64_t snapshot_id = 0,
    std::chrono::system_clock::time_point collected_at = std::chrono::system_clock::now(),
    std::chrono::steady_clock::time_point collected_monotonic = std::chrono::steady_clock::now());
[[nodiscard]] DashboardState make_dashboard_state(FirewallState firewall);
[[nodiscard]] std::string_view to_string(DashboardRisk risk);
[[nodiscard]] std::string_view to_string(DefconReadiness readiness);
[[nodiscard]] std::string_view to_string(MenuDestination destination);
[[nodiscard]] std::string format_dashboard_timestamp(std::chrono::system_clock::time_point timestamp);
[[nodiscard]] std::string format_dashboard_local_time(std::chrono::system_clock::time_point timestamp);
[[nodiscard]] std::string format_dashboard_age(const DashboardSnapshot& snapshot,
                                                std::chrono::steady_clock::time_point now =
                                                    std::chrono::steady_clock::now());

} // namespace ffc
