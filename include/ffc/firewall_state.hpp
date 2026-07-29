#pragma once

#include "ffc/network_manager.hpp"
#include "ffc/vpn.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/evidence_quality.hpp"
#include "ffc/operating_mode.hpp"

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace ffc {
// A false or empty value is only meaningful when the underlying command was
// collected and parsed. Partial is reserved for collectors that return a
// usable but incomplete view.
enum class ObservationStatus { Unavailable, Partial, Available };

[[nodiscard]] bool observation_available(ObservationStatus status);

struct ZoneState {
    std::string target;
    std::vector<std::string> interfaces;
    std::vector<std::string> sources;
    std::vector<std::string> services;
    std::vector<std::string> ports;
    std::vector<std::string> protocols;
    std::vector<std::string> source_ports;
    std::vector<std::string> rich_rules;
    std::vector<std::string> forward_ports;
    bool masquerade{false};
    bool forward{false};
    bool details_valid{true};
};

struct FirewallState {
    OperatingMode operating_mode{OperatingMode::Normal};
    OperatingModeLoadStatus operating_mode_status{OperatingModeLoadStatus::Defaulted};
    std::string operating_mode_diagnostic;
    bool installed{false};
    bool active{false};
    bool enabled{false};
    bool panic{false};
    bool permanent_config_valid{false};
    bool permanent_config_checked{false};
    ObservationStatus installation_status{ObservationStatus::Unavailable};
    ObservationStatus service_state{ObservationStatus::Unavailable};
    ObservationStatus service_enablement{ObservationStatus::Unavailable};
    ObservationStatus panic_state{ObservationStatus::Unavailable};
    ObservationStatus permanent_config{ObservationStatus::Unavailable};
    ObservationStatus default_zone_status{ObservationStatus::Unavailable};
    ObservationStatus denied_logging_status{ObservationStatus::Unavailable};
    ObservationStatus active_zones_status{ObservationStatus::Unavailable};
    ObservationStatus runtime_zones_status{ObservationStatus::Unavailable};
    ObservationStatus permanent_zones_status{ObservationStatus::Unavailable};
    ObservationStatus active_policies_status{ObservationStatus::Unavailable};
    std::string default_zone;
    std::string log_denied;
    std::map<std::string, std::vector<std::string>> active_zone_interfaces;
    std::map<std::string, std::vector<std::string>> active_zone_sources;
    std::vector<std::string> active_policies;
    NetworkManagerState network_manager;
    VpnState vpn;
    SocketState sockets;
    SecuritySignalsState security_signals;
    EvidenceQualityState evidence_quality;
    std::map<std::string, ZoneState> runtime_zones;
    std::map<std::string, ZoneState> permanent_zones;
    std::vector<std::string> errors;
};

std::vector<std::string> split_words(const std::string &text);
ZoneState parse_zone_info(const std::string &text);
std::map<std::string, ZoneState> parse_all_zone_info(const std::string &text);
std::map<std::string, std::vector<std::string>> parse_active_zones(const std::string &text);
std::map<std::string, std::vector<std::string>> parse_active_zone_sources(const std::string &text);
std::vector<std::string> parse_active_policy_names(const std::string &text);
bool zone_configurations_equal(const ZoneState &left, const ZoneState &right);
// NetworkManager commonly assigns interfaces at runtime, so operational policy
// drift is evaluated separately from interface membership.
bool zone_policies_equal(const ZoneState &left, const ZoneState &right);
[[nodiscard]] bool is_zone_active(const FirewallState &state, std::string_view zone);
// Physical transports can receive the firewalld default zone. Tunnel and
// loopback devices are assessed by their dedicated paths instead.
[[nodiscard]] bool is_connected_transport_device(const NetworkDeviceState& device);
[[nodiscard]] bool is_zone_applicable(const FirewallState &state, std::string_view zone);
[[nodiscard]] std::vector<std::string> applicable_zone_names(const FirewallState &state);
[[nodiscard]] std::size_t active_zone_member_count(const FirewallState &state,
                                                   std::string_view zone);
[[nodiscard]] bool applicable_zone_details_available(const FirewallState &state);
} // namespace ffc
