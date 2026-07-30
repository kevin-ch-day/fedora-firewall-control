#include "ffc/dashboard_json.hpp"

#include "ffc/socket_inspector.hpp"
#include "dashboard_json_support.hpp"

#include <chrono>
#include <set>
#include <sstream>
#include <string_view>

namespace ffc {
namespace {

using dashboard_json_detail::category;
using dashboard_json_detail::destination;
using dashboard_json_detail::evidence_status;
using dashboard_json_detail::iso_timestamp;
using dashboard_json_detail::quote;
using dashboard_json_detail::readiness;
using dashboard_json_detail::risk_level;
using dashboard_json_detail::severity;

void append_string_array(std::ostringstream &output, const std::vector<std::string> &values) {
    output << '[';
    for (std::size_t index = 0; index < values.size(); ++index)
        output << (index == 0U ? "" : ",") << quote(values[index]);
    output << ']';
}

void append_zone(std::ostringstream &output, const std::string &name, const ZoneState &zone,
                 const FirewallState &firewall) {
    output << "{\"name\":" << quote(name)
           << ",\"applicable\":" << (is_zone_applicable(firewall, name) ? "true" : "false")
           << ",\"active\":" << (is_zone_active(firewall, name) ? "true" : "false")
           << ",\"target\":" << quote(zone.target) << ",\"interfaces\":";
    append_string_array(output, zone.interfaces);
    output << ",\"sources\":";
    append_string_array(output, zone.sources);
    output << ",\"services\":";
    append_string_array(output, zone.services);
    output << ",\"ports\":";
    append_string_array(output, zone.ports);
    output << ",\"protocols\":";
    append_string_array(output, zone.protocols);
    output << ",\"source_ports\":";
    append_string_array(output, zone.source_ports);
    output << ",\"rich_rules\":";
    append_string_array(output, zone.rich_rules);
    output << ",\"forward_ports\":";
    append_string_array(output, zone.forward_ports);
    output << ",\"masquerade\":" << (zone.masquerade ? "true" : "false")
           << ",\"forward\":" << (zone.forward ? "true" : "false")
           << ",\"details_valid\":" << (zone.details_valid ? "true" : "false") << '}';
}

void append_zones(std::ostringstream &output, const std::map<std::string, ZoneState> &zones,
                  const ObservationStatus status, const FirewallState &firewall) {
    if (!observation_available(status)) {
        output << "null";
        return;
    }
    output << '[';
    std::size_t index = 0;
    for (const auto &[name, zone] : zones) {
        output << (index++ == 0U ? "" : ",");
        append_zone(output, name, zone, firewall);
    }
    output << ']';
}

std::vector<std::string> drift_dimensions(const ZoneState &runtime, const ZoneState &permanent) {
    std::vector<std::string> dimensions;
    const auto changed = [&dimensions](const bool differs, const std::string_view name) {
        if (differs)
            dimensions.emplace_back(name);
    };
    changed(runtime.target != permanent.target, "target");
    changed(runtime.sources != permanent.sources, "sources");
    changed(runtime.services != permanent.services, "services");
    changed(runtime.ports != permanent.ports, "ports");
    changed(runtime.protocols != permanent.protocols, "protocols");
    changed(runtime.source_ports != permanent.source_ports, "source_ports");
    changed(runtime.rich_rules != permanent.rich_rules, "rich_rules");
    changed(runtime.forward_ports != permanent.forward_ports, "forward_ports");
    changed(runtime.masquerade != permanent.masquerade, "masquerade");
    changed(runtime.forward != permanent.forward, "forward");
    changed(runtime.details_valid != permanent.details_valid, "details_valid");
    return dimensions;
}

void append_drift(std::ostringstream &output, const FirewallState &firewall) {
    if (!observation_available(firewall.runtime_zones_status) ||
        !observation_available(firewall.permanent_zones_status)) {
        output << "null";
        return;
    }
    std::set<std::string> names;
    for (const auto &[name, zone] : firewall.runtime_zones) {
        (void)zone;
        names.insert(name);
    }
    for (const auto &[name, zone] : firewall.permanent_zones) {
        (void)zone;
        names.insert(name);
    }
    output << '[';
    std::size_t written = 0;
    for (const auto &name : names) {
        const auto runtime = firewall.runtime_zones.find(name);
        const auto permanent = firewall.permanent_zones.find(name);
        std::vector<std::string> dimensions;
        if (runtime == firewall.runtime_zones.end())
            dimensions.emplace_back("runtime_missing");
        else if (permanent == firewall.permanent_zones.end())
            dimensions.emplace_back("permanent_missing");
        else
            dimensions = drift_dimensions(runtime->second, permanent->second);
        if (dimensions.empty())
            continue;
        output << (written++ == 0U ? "" : ",") << "{\"zone\":" << quote(name)
               << ",\"runtime_present\":"
               << (runtime != firewall.runtime_zones.end() ? "true" : "false")
               << ",\"permanent_present\":"
               << (permanent != firewall.permanent_zones.end() ? "true" : "false")
               << ",\"dimensions\":";
        append_string_array(output, dimensions);
        output << '}';
    }
    output << ']';
}

std::string listener_scope(const ListeningSocket &listener) {
    return listener.loopback_only    ? "loopback"
           : listener.multicast_only ? "multicast"
                                     : "network_reachable";
}

void append_listeners(std::ostringstream &output, const SocketState &sockets) {
    if (!sockets.available) {
        output << "null";
        return;
    }
    output << '[';
    for (std::size_t index = 0; index < sockets.listeners.size(); ++index) {
        const auto &listener = sockets.listeners[index];
        output << (index == 0U ? "" : ",") << "{\"protocol\":" << quote(listener.protocol)
               << ",\"endpoint\":" << quote(listener.endpoint)
               << ",\"scope\":" << quote(listener_scope(listener)) << ",\"process_name\":"
               << (listener.process_name.empty() ? "null" : quote(listener.process_name)) << '}';
    }
    output << ']';
}

void append_finding(std::ostringstream &output, const DashboardFinding &finding) {
    output << "{\"id\":" << quote(finding.id)
           << ",\"severity\":" << quote(severity(finding.severity))
           << ",\"category\":" << quote(category(finding.category))
           << ",\"summary\":" << quote(finding.summary)
           << ",\"destination\":" << quote(destination(finding.destination)) << '}';
}

void append_findings(std::ostringstream &output, const std::vector<DashboardFinding> &findings) {
    output << '[';
    for (std::size_t index = 0; index < findings.size(); ++index) {
        output << (index == 0U ? "" : ",");
        append_finding(output, findings[index]);
    }
    output << ']';
}

void append_recommendation(std::ostringstream &output,
                           const DashboardRecommendation &recommendation) {
    output << "{\"id\":" << quote(recommendation.finding_id)
           << ",\"severity\":" << quote(severity(recommendation.severity))
           << ",\"category\":" << quote(category(recommendation.category))
           << ",\"summary\":" << quote(recommendation.summary)
           << ",\"destination\":" << quote(destination(recommendation.destination)) << '}';
}

std::string active_interface_v2(const FirewallState &firewall) {
    for (const auto &[zone, interfaces] : firewall.active_zone_interfaces) {
        (void)zone;
        if (!interfaces.empty())
            return interfaces.front();
    }
    return {};
}

std::string active_zone_v2(const FirewallState &firewall) {
    for (const auto &[zone, interfaces] : firewall.active_zone_interfaces)
        if (!interfaces.empty())
            return zone;
    for (const auto &[zone, sources] : firewall.active_zone_sources)
        if (!sources.empty())
            return zone;
    return firewall.default_zone;
}

std::string nullable_string(const std::string &value, const ObservationStatus status) {
    return observation_available(status) ? quote(value) : "null";
}

std::string nullable_bool(const bool value, const ObservationStatus status) {
    return observation_available(status) ? (value ? "true" : "false") : "null";
}

std::string nullable_count(const std::size_t value, const ObservationStatus status) {
    return observation_available(status) ? std::to_string(value) : "null";
}

} // namespace

std::string serialize_dashboard_snapshot_json_v2(const DashboardSnapshot &snapshot) {
    const auto &firewall = snapshot.firewall;
    const auto listener_summary = summarize_listener_exposure(firewall.sockets);
    const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - snapshot.collected_monotonic)
                         .count();
    const auto primary = snapshot.recommendations.empty() ? DashboardRecommendation{}
                                                          : snapshot.recommendations.front();

    std::size_t ports = 0;
    std::size_t protocols = 0;
    std::size_t rich_rules = 0;
    bool forwarding = false;
    for (const auto &[name, zone] : firewall.runtime_zones) {
        if (!is_zone_applicable(firewall, name))
            continue;
        ports += zone.ports.size();
        protocols += zone.protocols.size();
        rich_rules += zone.rich_rules.size();
        forwarding = forwarding || zone.forward;
    }

    std::ostringstream output;
    output
        << "{\n  \"schema\": \"ffc.dashboard.v2\",\n"
        << "  \"schema_version\": 2,\n"
        << "  \"snapshot_id\": " << snapshot.snapshot_id << ",\n"
        << "  \"hostname\": " << quote(snapshot.hostname) << ",\n"
        << "  \"application_version\": " << quote(snapshot.application_version) << ",\n"
        << "  \"collected_at\": " << quote(iso_timestamp(snapshot.collected_at)) << ",\n"
        << "  \"age_ms\": " << (age < 0 ? 0 : age) << ",\n"
        << "  \"stale\": " << (age >= 30000 ? "true" : "false") << ",\n"
        << "  \"status\": " << quote(evidence_status(snapshot.overall_evidence)) << ",\n"
        << "  \"assessment\": {\"mode\":"
        << quote(firewall.operating_mode == OperatingMode::HostileNetwork ? "hostile" : "normal")
        << ",\"defcon_readiness\":" << quote(readiness(snapshot.defcon_readiness)) << "},\n"
        << "  \"risk\": {\"level\":" << quote(risk_level(snapshot.risk))
        << ",\"blockers\":" << snapshot.blockers.size()
        << ",\"review_items\":" << snapshot.review_items.size()
        << ",\"coverage_gaps\":" << snapshot.coverage_gaps.size() << "},\n"
        << "  \"firewall\": {\"active_status\":" << quote(evidence_status(firewall.service_state))
        << ",\"active\":" << nullable_bool(firewall.active, firewall.service_state)
        << ",\"enabled_status\":" << quote(evidence_status(firewall.service_enablement))
        << ",\"enabled\":" << nullable_bool(firewall.enabled, firewall.service_enablement)
        << ",\"default_zone_status\":" << quote(evidence_status(firewall.default_zone_status))
        << ",\"default_zone\":"
        << nullable_string(firewall.default_zone, firewall.default_zone_status)
        << ",\"runtime_zones_status\":" << quote(evidence_status(firewall.runtime_zones_status))
        << ",\"permanent_zones_status\":" << quote(evidence_status(firewall.permanent_zones_status))
        << ",\"active_policies_status\":" << quote(evidence_status(firewall.active_policies_status))
        << ",\"inbound_port_rules\":" << nullable_count(ports, firewall.runtime_zones_status)
        << ",\"protocol_rules\":" << nullable_count(protocols, firewall.runtime_zones_status)
        << ",\"rich_rules\":" << nullable_count(rich_rules, firewall.runtime_zones_status)
        << ",\"intra_zone_forwarding\":" << nullable_bool(forwarding, firewall.runtime_zones_status)
        << ",\"runtime_zones\":";
    append_zones(output, firewall.runtime_zones, firewall.runtime_zones_status, firewall);
    output << ",\"permanent_zones\":";
    append_zones(output, firewall.permanent_zones, firewall.permanent_zones_status, firewall);
    output << ",\"active_policies\":";
    if (observation_available(firewall.active_policies_status))
        append_string_array(output, firewall.active_policies);
    else
        output << "null";
    output << ",\"runtime_permanent_drift\":";
    append_drift(output, firewall);
    output << "},\n  \"listeners\": {\"status\":"
           << quote(evidence_status(firewall.sockets.available ? ObservationStatus::Available
                                                               : ObservationStatus::Unavailable))
           << ",\"tcp_udp_listeners\":"
           << nullable_count(listener_summary.logical_network_services,
                             firewall.sockets.available ? ObservationStatus::Available
                                                        : ObservationStatus::Unavailable)
           << ",\"reachable_bindings\":"
           << nullable_count(listener_summary.network_reachable_bindings,
                             firewall.sockets.available ? ObservationStatus::Available
                                                        : ObservationStatus::Unavailable)
           << ",\"process_metadata_requested\":"
           << (firewall.sockets.process_metadata_requested ? "true" : "false") << ",\"bindings\":";
    append_listeners(output, firewall.sockets);
    output << "},\n  \"network\": {\"physical_interface\":"
           << nullable_string(active_interface_v2(firewall), firewall.active_zones_status)
           << ",\"zone\":"
           << nullable_string(active_zone_v2(firewall), firewall.active_zones_status)
           << ",\"network_manager\":{\"device_inventory_status\":"
           << quote(evidence_status(firewall.network_manager.available
                                        ? ObservationStatus::Available
                                        : ObservationStatus::Unavailable))
           << ",\"profile_inventory_status\":\"unavailable\",\"profile\":null,\"autoconnect\":null,"
              "\"diagnostic\":"
           << quote(firewall.network_manager.available
                        ? "profile and autoconnect inventory are not collected by this "
                          "read-only snapshot"
                        : firewall.network_manager.diagnostic)
           << "},\"tunnel_detection\":{\"status\":"
           << quote(evidence_status(firewall.vpn.interface_scan_available
                                        ? ObservationStatus::Available
                                        : ObservationStatus::Unavailable))
           << ",\"tunnel_interface\":"
           << nullable_string(firewall.vpn.active_tunnel_interfaces.empty()
                                  ? std::string{}
                                  : firewall.vpn.active_tunnel_interfaces.front(),
                              firewall.vpn.interface_scan_available
                                  ? ObservationStatus::Available
                                  : ObservationStatus::Unavailable)
           << "},\"vpn_route\":{\"status\":\"unavailable\",\"uses_tunnel\":null,\"diagnostic\":"
              "\"route verification is not implemented\"}"
           << ",\"dns_path\":{\"status\":\"unavailable\",\"uses_tunnel\":null,\"diagnostic\":\"DNS "
              "path verification is not implemented\"}"
           << ",\"kill_switch\":{\"status\":\"unavailable\",\"enabled\":null,\"diagnostic\":\"kill-"
              "switch verification is not implemented\"}},\n"
           << "  \"findings\": {\"blockers\":";
    append_findings(output, snapshot.blockers);
    output << ",\"review_items\":";
    append_findings(output, snapshot.review_items);
    output << ",\"coverage_gaps\":";
    append_findings(output, snapshot.coverage_gaps);
    output << "},\n  \"recommendations\": [";
    for (std::size_t index = 0; index < snapshot.recommendations.size(); ++index) {
        output << (index == 0U ? "" : ",");
        append_recommendation(output, snapshot.recommendations[index]);
    }
    output << "],\n  \"recommendation\": ";
    append_recommendation(output, primary);
    output << ",\n  \"evidence\": {\"status\":" << quote(evidence_status(snapshot.overall_evidence))
           << ",\"components\":[";
    for (std::size_t index = 0; index < snapshot.evidence_components.size(); ++index) {
        const auto &component = snapshot.evidence_components[index];
        output << (index == 0U ? "" : ",") << "{\"component\":" << quote(component.component)
               << ",\"status\":" << quote(evidence_status(component.status))
               << ",\"detail\":" << quote(component.detail) << '}';
    }
    output << "]}\n}\n";
    return output.str();
}

} // namespace ffc
