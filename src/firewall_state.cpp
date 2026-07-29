#include "ffc/firewall_state.hpp"

#include <algorithm>
#include <sstream>

namespace ffc {
std::vector<std::string> split_words(const std::string& text) {
    std::istringstream input(text); std::vector<std::string> result; std::string word;
    while (input >> word) result.push_back(word);
    return result;
}

ZoneState parse_zone_info(const std::string& text) {
    ZoneState zone; std::istringstream lines(text); std::string line;
    while (std::getline(lines, line)) {
        if (line.find("rule ") != std::string::npos) { zone.rich_rules.push_back(line); continue; }
        const auto colon = line.find(':'); if (colon == std::string::npos) continue;
        auto key = line.substr(0, colon); auto value = line.substr(colon + 1);
        const auto first = key.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        key.erase(0, first); key.erase(key.find_last_not_of(" \t") + 1);
        if (key == "interfaces") zone.interfaces = split_words(value);
        else if (key == "services") zone.services = split_words(value);
        else if (key == "ports") zone.ports = split_words(value);
        else if (key == "rich rules") { if (!value.empty() && value.find_first_not_of(" \t") != std::string::npos) zone.rich_rules.push_back(value); }
        else if (key == "masquerade") zone.masquerade = value.find("yes") != std::string::npos;
        else if (key == "forward") zone.forward = value.find("yes") != std::string::npos;
    }
    return zone;
}

std::map<std::string, std::vector<std::string>> parse_active_zones(const std::string& text) {
    std::map<std::string, std::vector<std::string>> zones;
    std::istringstream lines(text); std::string line; std::string current_zone;
    while (std::getline(lines, line)) {
        if (line.empty()) continue;
        if (line.front() != ' ' && line.front() != '\t') {
            const auto words = split_words(line);
            current_zone = words.empty() ? std::string{} : words.front();
            continue;
        }
        const auto colon = line.find(':');
        if (current_zone.empty() || colon == std::string::npos) continue;
        const auto key = line.substr(0, colon);
        if (key.find("interfaces") != std::string::npos) zones[current_zone] = split_words(line.substr(colon + 1));
    }
    return zones;
}

bool zone_configurations_equal(const ZoneState& a, const ZoneState& b) {
    return a.interfaces == b.interfaces && a.services == b.services && a.ports == b.ports && a.rich_rules == b.rich_rules &&
        a.masquerade == b.masquerade && a.forward == b.forward;
}
} // namespace ffc
