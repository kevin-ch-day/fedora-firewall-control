#pragma once

#include <map>
#include <string>
#include <vector>

namespace ffc {
struct ZoneState {
    std::vector<std::string> interfaces;
    std::vector<std::string> services;
    std::vector<std::string> ports;
    std::vector<std::string> rich_rules;
    bool masquerade{false};
    bool forward{false};
};

struct FirewallState {
    bool installed{false};
    bool active{false};
    bool enabled{false};
    bool panic{false};
    std::string default_zone;
    std::map<std::string, std::vector<std::string>> active_zone_interfaces;
    std::map<std::string, ZoneState> runtime_zones;
    std::map<std::string, ZoneState> permanent_zones;
    std::vector<std::string> errors;
};

std::vector<std::string> split_words(const std::string& text);
ZoneState parse_zone_info(const std::string& text);
std::map<std::string, std::vector<std::string>> parse_active_zones(const std::string& text);
bool zone_configurations_equal(const ZoneState& left, const ZoneState& right);
} // namespace ffc
