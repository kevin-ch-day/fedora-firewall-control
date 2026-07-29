#include "ffc/firewall_state.hpp"

#include <algorithm>
#include <set>
#include <sstream>

namespace ffc {
namespace {
std::string sanitize_terminal_identifier(const std::string_view value) {
    std::string sanitized;
    sanitized.reserve(value.size());
    for (const unsigned char character : value)
        sanitized += character >= 0x20U && character <= 0x7eU ? static_cast<char>(character) : '?';
    return sanitized;
}
} // namespace

bool observation_available(const ObservationStatus status) {
    return status == ObservationStatus::Available;
}

std::vector<std::string> split_words(const std::string &text) {
    std::istringstream input(text);
    std::vector<std::string> result;
    std::string word;
    while (input >> word)
        result.push_back(word);
    return result;
}

ZoneState parse_zone_info(const std::string &text) {
    ZoneState zone;
    std::istringstream lines(text);
    std::string line;
    bool reading_forward_ports = false;
    while (std::getline(lines, line)) {
        if (line.find("rule ") != std::string::npos) {
            zone.rich_rules.push_back(line);
            continue;
        }
        if (reading_forward_ports && line.find("port=") != std::string::npos) {
            zone.forward_ports.push_back(line);
            continue;
        }
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            if (reading_forward_ports && line.find_first_not_of(" \t") != std::string::npos)
                zone.forward_ports.push_back(line);
            continue;
        }
        auto key = line.substr(0, colon);
        auto value = line.substr(colon + 1);
        const auto first = key.find_first_not_of(" \t");
        if (first == std::string::npos)
            continue;
        key.erase(0, first);
        key.erase(key.find_last_not_of(" \t") + 1);
        reading_forward_ports = key == "forward-ports";
        if (key == "target") {
            const auto values = split_words(value);
            if (values.size() == 1U)
                zone.target = values.front();
            else
                zone.details_valid = false;
        } else if (key == "interfaces")
            zone.interfaces = split_words(value);
        else if (key == "sources")
            zone.sources = split_words(value);
        else if (key == "services")
            zone.services = split_words(value);
        else if (key == "ports")
            zone.ports = split_words(value);
        else if (key == "protocols")
            zone.protocols = split_words(value);
        else if (key == "source-ports")
            zone.source_ports = split_words(value);
        else if (key == "forward-ports" && value.find_first_not_of(" \t") != std::string::npos)
            zone.forward_ports.push_back(value);
        else if (key == "rich rules") {
            if (!value.empty() && value.find_first_not_of(" \t") != std::string::npos)
                zone.rich_rules.push_back(value);
        } else if (key == "masquerade" || key == "forward") {
            const auto values = split_words(value);
            if (values.size() != 1U || (values.front() != "yes" && values.front() != "no")) {
                zone.details_valid = false;
                continue;
            }
            const bool enabled = values.front() == "yes";
            if (key == "masquerade")
                zone.masquerade = enabled;
            else
                zone.forward = enabled;
        }
    }
    return zone;
}

std::map<std::string, ZoneState> parse_all_zone_info(const std::string &text) {
    std::map<std::string, ZoneState> zones;
    std::istringstream lines(text);
    std::string line, current_name, current_zone;
    const auto save_zone = [&]() {
        if (!current_name.empty())
            zones.emplace(current_name, parse_zone_info(current_zone));
    };
    while (std::getline(lines, line)) {
        if (!line.empty() && line.front() != ' ' && line.front() != '\t') {
            save_zone();
            const auto names = split_words(line);
            current_name = names.empty() ? std::string{} : names.front();
            current_zone.clear();
        } else if (!current_name.empty()) {
            current_zone += line + '\n';
        }
    }
    save_zone();
    return zones;
}

std::map<std::string, std::vector<std::string>> parse_active_zones(const std::string &text) {
    std::map<std::string, std::vector<std::string>> zones;
    std::istringstream lines(text);
    std::string line;
    std::string current_zone;
    while (std::getline(lines, line)) {
        if (line.empty())
            continue;
        if (line.front() != ' ' && line.front() != '\t') {
            const auto words = split_words(line);
            current_zone = words.empty() ? std::string{} : words.front();
            continue;
        }
        const auto colon = line.find(':');
        if (current_zone.empty() || colon == std::string::npos)
            continue;
        const auto key = line.substr(0, colon);
        if (key.find("interfaces") != std::string::npos)
            zones[current_zone] = split_words(line.substr(colon + 1));
    }
    return zones;
}

std::map<std::string, std::vector<std::string>> parse_active_zone_sources(const std::string &text) {
    std::map<std::string, std::vector<std::string>> zones;
    std::istringstream lines(text);
    std::string line;
    std::string current_zone;
    while (std::getline(lines, line)) {
        if (line.empty())
            continue;
        if (line.front() != ' ' && line.front() != '\t') {
            const auto words = split_words(line);
            current_zone = words.empty() ? std::string{} : words.front();
            continue;
        }
        const auto colon = line.find(':');
        if (current_zone.empty() || colon == std::string::npos)
            continue;
        const auto key = line.substr(0, colon);
        if (key.find("sources") != std::string::npos)
            zones[current_zone] = split_words(line.substr(colon + 1));
    }
    return zones;
}

std::vector<std::string> parse_active_policy_names(const std::string &text) {
    std::vector<std::string> policies;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.empty() || line.front() == ' ' || line.front() == '\t')
            continue;
        const auto words = split_words(line);
        if (!words.empty())
            policies.push_back(sanitize_terminal_identifier(words.front()));
    }
    return policies;
}

namespace {
bool unordered_values_equal(std::vector<std::string> left, std::vector<std::string> right) {
    std::sort(left.begin(), left.end());
    std::sort(right.begin(), right.end());
    return left == right;
}

bool zone_policy_values_equal(const ZoneState &left, const ZoneState &right) {
    // Rich-rule ordering can affect evaluation, so it intentionally remains
    // order-sensitive. The other values are unordered firewalld collections.
    return left.target == right.target && unordered_values_equal(left.sources, right.sources) &&
           unordered_values_equal(left.services, right.services) &&
           unordered_values_equal(left.ports, right.ports) &&
           unordered_values_equal(left.protocols, right.protocols) &&
           unordered_values_equal(left.source_ports, right.source_ports) &&
           left.rich_rules == right.rich_rules &&
           unordered_values_equal(left.forward_ports, right.forward_ports) &&
           left.masquerade == right.masquerade && left.forward == right.forward &&
           left.details_valid == right.details_valid;
}
} // namespace

bool zone_configurations_equal(const ZoneState &left, const ZoneState &right) {
    return unordered_values_equal(left.interfaces, right.interfaces) &&
           zone_policy_values_equal(left, right);
}

bool zone_policies_equal(const ZoneState &left, const ZoneState &right) {
    return zone_policy_values_equal(left, right);
}

bool is_zone_active(const FirewallState &state, const std::string_view zone) {
    const std::string name{zone};
    return state.active_zone_interfaces.contains(name) || state.active_zone_sources.contains(name);
}

bool is_connected_transport_device(const NetworkDeviceState& device) {
    if (device.state.rfind("connected", 0) != 0)
        return false;
    return device.type != "loopback" && device.type != "wireguard" && device.type != "tun" &&
           device.type != "vpn";
}

std::vector<std::string> applicable_zone_names(const FirewallState &state) {
    std::set<std::string> zones;
    for (const auto &[zone, ignored] : state.active_zone_interfaces) {
        (void)ignored;
        zones.insert(zone);
    }
    for (const auto &[zone, ignored] : state.active_zone_sources) {
        (void)ignored;
        zones.insert(zone);
    }

    bool default_zone_applies = !state.network_manager.available;
    if (state.network_manager.available) {
        for (const auto &device : state.network_manager.devices) {
            if (!is_connected_transport_device(device))
                continue;
            bool explicitly_bound = false;
            for (const auto &[zone, interfaces] : state.active_zone_interfaces) {
                (void)zone;
                explicitly_bound = explicitly_bound ||
                                   std::find(interfaces.begin(), interfaces.end(),
                                             device.interface_name) != interfaces.end();
            }
            default_zone_applies = default_zone_applies || !explicitly_bound;
        }
    }
    if (default_zone_applies && observation_available(state.default_zone_status) &&
        !state.default_zone.empty())
        zones.insert(state.default_zone);
    return {zones.begin(), zones.end()};
}

bool is_zone_applicable(const FirewallState &state, const std::string_view zone) {
    const auto names = applicable_zone_names(state);
    return std::find(names.begin(), names.end(), zone) != names.end();
}

std::size_t active_zone_member_count(const FirewallState &state, const std::string_view zone) {
    const std::string name{zone};
    const auto interface_count = state.active_zone_interfaces.contains(name)
                                     ? state.active_zone_interfaces.at(name).size()
                                     : 0U;
    const auto source_count =
        state.active_zone_sources.contains(name) ? state.active_zone_sources.at(name).size() : 0U;
    return interface_count + source_count;
}

bool applicable_zone_details_available(const FirewallState &state) {
    if (!observation_available(state.active_zones_status) ||
        !observation_available(state.runtime_zones_status) ||
        !observation_available(state.default_zone_status))
        return false;
    for (const auto &zone : applicable_zone_names(state)) {
        if (!state.runtime_zones.contains(zone))
            return false;
    }
    return true;
}
} // namespace ffc
