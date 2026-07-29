#include "ffc/dashboard_json.hpp"

#include "ffc/socket_inspector.hpp"

#include <iomanip>
#include <sstream>

namespace ffc {
namespace {

std::string json_escape(const std::string_view value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (character < 0x20U)
                output << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<unsigned int>(character) << std::dec << std::setfill(' ');
            else
                output << static_cast<char>(character);
        }
    }
    return output.str();
}

std::string iso_timestamp(const std::chrono::system_clock::time_point timestamp) {
    const auto time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm utc{};
    gmtime_r(&time, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::string risk_level(const DashboardRisk risk) {
    switch (risk) {
    case DashboardRisk::Ready: return "ready";
    case DashboardRisk::Review: return "review_required";
    case DashboardRisk::Blocked: return "blocked";
    }
    return "review_required";
}

std::string defcon_readiness(const DefconReadiness readiness) {
    switch (readiness) {
    case DefconReadiness::NotEvaluated: return "not_evaluated";
    case DefconReadiness::Ready: return "ready";
    case DefconReadiness::NotReady: return "not_ready";
    }
    return "not_evaluated";
}

std::string finding_category(const FindingCategory category) {
    switch (category) {
    case FindingCategory::Isolation: return "isolation";
    case FindingCategory::Firewall: return "firewall_failure";
    case FindingCategory::Exposure: return "firewall_exposure";
    case FindingCategory::Listener: return "listener_exposure";
    case FindingCategory::Change: return "configuration_change";
    case FindingCategory::EvidenceGap: return "evidence_gap";
    case FindingCategory::Hygiene: return "hygiene";
    }
    return "hygiene";
}

std::string destination_id(const MenuDestination destination) {
    switch (destination) {
    case MenuDestination::Readiness: return "readiness";
    case MenuDestination::Signals: return "signals";
    case MenuDestination::Firewall: return "firewall.active_openings";
    case MenuDestination::Network: return "network";
    case MenuDestination::Evidence: return "evidence";
    case MenuDestination::Settings: return "settings";
    case MenuDestination::Emergency: return "emergency";
    }
    return "readiness";
}

std::string evidence_status(const ObservationStatus status) {
    return status == ObservationStatus::Available ? "available"
           : status == ObservationStatus::Partial ? "partial" : "unavailable";
}

std::string json_observation(const ObservationStatus status) {
    return "\"" + evidence_status(status) + "\"";
}

std::string json_bool(const bool value, const ObservationStatus status) {
    return status == ObservationStatus::Available ? (value ? "true" : "false") : "null";
}

std::string json_count(const std::size_t value, const ObservationStatus status) {
    return status == ObservationStatus::Available ? std::to_string(value) : "null";
}

std::string json_string(const std::string& value, const ObservationStatus status) {
    return status == ObservationStatus::Available ? "\"" + json_escape(value) + "\"" : "null";
}

std::string severity(const FindingSeverity value) {
    switch (value) {
    case FindingSeverity::Critical: return "critical";
    case FindingSeverity::High: return "high";
    case FindingSeverity::Medium: return "medium";
    case FindingSeverity::Low: return "low";
    case FindingSeverity::Information: return "information";
    }
    return "information";
}

std::string active_interface(const FirewallState& state) {
    for (const auto& [zone, interfaces] : state.active_zone_interfaces) {
        (void)zone;
        if (!interfaces.empty())
            return interfaces.front();
    }
    return {};
}

std::string active_zone(const FirewallState& state) {
    for (const auto& [zone, interfaces] : state.active_zone_interfaces) {
        if (!interfaces.empty())
            return zone;
    }
    return state.default_zone;
}

} // namespace

std::string serialize_dashboard_snapshot_json(const DashboardSnapshot& snapshot) {
    std::size_t ports = 0;
    std::size_t protocols = 0;
    std::size_t rich_rules = 0;
    bool forwarding = false;
    for (const auto& [name, zone] : snapshot.firewall.runtime_zones) {
        if (!is_zone_applicable(snapshot.firewall, name))
            continue;
        ports += zone.ports.size();
        protocols += zone.protocols.size();
        rich_rules += zone.rich_rules.size();
        forwarding = forwarding || zone.forward;
    }
    const auto listeners = summarize_listener_exposure(snapshot.firewall.sockets);
    const auto recommendation = snapshot.recommendations.empty() ? DashboardRecommendation{}
                                                                  : snapshot.recommendations.front();
    const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - snapshot.collected_monotonic).count();
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\": \"ffc.dashboard.v1\",\n"
           << "  \"schema_version\": " << DashboardSnapshot::schema_version << ",\n"
           << "  \"snapshot_id\": " << snapshot.snapshot_id << ",\n"
           << "  \"hostname\": \"" << json_escape(snapshot.hostname) << "\",\n"
           << "  \"application_version\": \"" << json_escape(snapshot.application_version) << "\",\n"
           << "  \"collected_at\": \"" << iso_timestamp(snapshot.collected_at) << "\",\n"
           << "  \"age_ms\": " << (age < 0 ? 0 : age) << ",\n"
           << "  \"stale\": " << (age >= 30000 ? "true" : "false") << ",\n"
           << "  \"status\": " << json_observation(snapshot.overall_evidence) << ",\n"
           << "  \"assessment\": {\"mode\": \""
           << (snapshot.firewall.operating_mode == OperatingMode::HostileNetwork ? "hostile" : "normal")
           << "\", \"defcon_readiness\": \"" << defcon_readiness(snapshot.defcon_readiness) << "\"},\n"
           << "  \"risk\": {\"level\": \"" << risk_level(snapshot.risk) << "\", \"blockers\": "
           << snapshot.blockers.size() << ", \"review_items\": " << snapshot.review_items.size()
           << ", \"coverage_gaps\": " << snapshot.coverage_gaps.size() << "},\n"
           << "  \"firewall\": {\"active_status\": " << json_observation(snapshot.firewall.service_state)
           << ", \"active\": " << json_bool(snapshot.firewall.active, snapshot.firewall.service_state)
           << ", \"enabled_status\": " << json_observation(snapshot.firewall.service_enablement)
           << ", \"enabled\": " << json_bool(snapshot.firewall.enabled, snapshot.firewall.service_enablement)
           << ", \"default_zone_status\": " << json_observation(snapshot.firewall.default_zone_status)
           << ", \"default_zone\": " << json_string(snapshot.firewall.default_zone, snapshot.firewall.default_zone_status)
           << ", \"policy_status\": " << json_observation(snapshot.firewall.runtime_zones_status)
           << ", \"inbound_port_rules\": " << json_count(ports, snapshot.firewall.runtime_zones_status)
           << ", \"protocol_rules\": " << json_count(protocols, snapshot.firewall.runtime_zones_status)
           << ", \"rich_rules\": " << json_count(rich_rules, snapshot.firewall.runtime_zones_status)
           << ", \"intra_zone_forwarding\": " << json_bool(forwarding, snapshot.firewall.runtime_zones_status) << "},\n"
           << "  \"listeners\": {\"status\": " << json_observation(snapshot.firewall.sockets.available ? ObservationStatus::Available : ObservationStatus::Unavailable)
           << ", \"tcp_udp_listeners\": " << json_count(listeners.logical_network_services, snapshot.firewall.sockets.available ? ObservationStatus::Available : ObservationStatus::Unavailable)
           << ", \"reachable_bindings\": " << json_count(listeners.network_reachable_bindings, snapshot.firewall.sockets.available ? ObservationStatus::Available : ObservationStatus::Unavailable) << "},\n"
           << "  \"network\": {\"physical_interface\": " << json_string(active_interface(snapshot.firewall), snapshot.firewall.active_zones_status)
           << ", \"zone\": " << json_string(active_zone(snapshot.firewall), snapshot.firewall.active_zones_status)
           << ", \"network_manager\": {\"device_inventory_status\": " << json_observation(snapshot.firewall.network_manager.available ? ObservationStatus::Available : ObservationStatus::Unavailable)
           << ", \"profile_inventory_status\": \"unavailable\", \"profile\": null, \"autoconnect\": null, \"diagnostic\": \""
           << json_escape(snapshot.firewall.network_manager.available
                              ? "profile and autoconnect inventory are not collected by this read-only snapshot"
                              : snapshot.firewall.network_manager.diagnostic) << "\"}"
           << ", \"tunnel_detection\": {\"status\": " << json_observation(snapshot.firewall.vpn.interface_scan_available ? ObservationStatus::Available : ObservationStatus::Unavailable)
           << ", \"tunnel_interface\": " << json_string(snapshot.firewall.vpn.active_tunnel_interfaces.empty() ? "" : snapshot.firewall.vpn.active_tunnel_interfaces.front(), snapshot.firewall.vpn.interface_scan_available ? ObservationStatus::Available : ObservationStatus::Unavailable) << "}"
           << ", \"vpn_route\": {\"status\": \"unavailable\", \"uses_tunnel\": null, \"diagnostic\": \"route verification is not implemented\"}"
           << ", \"dns_path\": {\"status\": \"unavailable\", \"uses_tunnel\": null, \"diagnostic\": \"DNS path verification is not implemented\"}"
           << ", \"kill_switch\": {\"status\": \"unavailable\", \"enabled\": null, \"diagnostic\": \"kill-switch verification is not implemented\"}},\n"
           << "  \"evidence\": {\"status\": \"" << evidence_status(snapshot.overall_evidence)
           << "\", \"components\": [";
    for (std::size_t index = 0; index < snapshot.evidence_components.size(); ++index) {
        const auto& component = snapshot.evidence_components[index];
        output << (index == 0U ? "" : ",") << "{\"component\":\"" << json_escape(component.component)
               << "\",\"status\":\"" << evidence_status(component.status) << "\",\"detail\":\""
               << json_escape(component.detail) << "\"}";
    }
    output << "]},\n"
           << "  \"recommendation\": {\"id\": \"" << json_escape(recommendation.finding_id)
           << "\", \"severity\": \"" << severity(recommendation.severity)
           << "\", \"category\": \"" << finding_category(recommendation.category)
           << "\", \"summary\": \"" << json_escape(recommendation.summary)
           << "\", \"destination\": \"" << destination_id(recommendation.destination)
           << "\"}\n}" << '\n';
    return output.str();
}

} // namespace ffc
