#pragma once

#include "ffc/network_manager.hpp"
#include "ffc/vpn.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/evidence_quality.hpp"
#include "ffc/operating_mode.hpp"

#include <map>
#include <string>
#include <vector>

namespace ffc {
struct ZoneState {
    std::string target;
    std::vector<std::string> interfaces;
    std::vector<std::string> sources;
    std::vector<std::string> services;
    std::vector<std::string> ports;
    std::vector<std::string> rich_rules;
    std::vector<std::string> forward_ports;
    bool masquerade{false};
    bool forward{false};
};

struct FirewallState {
    OperatingMode operating_mode{OperatingMode::Normal};
    bool installed{false};
    bool active{false};
    bool enabled{false};
    bool panic{false};
    bool permanent_config_valid{false};
    bool permanent_config_checked{false};
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

std::vector<std::string> split_words(const std::string& text);
ZoneState parse_zone_info(const std::string& text);
std::map<std::string, std::vector<std::string>> parse_active_zones(const std::string& text);
std::map<std::string, std::vector<std::string>> parse_active_zone_sources(const std::string& text);
std::vector<std::string> parse_active_policy_names(const std::string& text);
bool zone_configurations_equal(const ZoneState& left, const ZoneState& right);
// NetworkManager commonly assigns interfaces at runtime, so operational policy
// drift is evaluated separately from interface membership.
bool zone_policies_equal(const ZoneState& left, const ZoneState& right);
} // namespace ffc
