#include "ffc/network_route.hpp"

#include <charconv>
#include <cstdlib>
#include <sstream>

namespace ffc {
std::vector<TracerouteHop> parse_traceroute_hops(const std::string& traceroute_output) {
    std::vector<TracerouteHop> hops;
    std::istringstream lines(traceroute_output);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string hop_number, address;
        if (!(fields >> hop_number >> address) || address == "*") continue;
        unsigned int number{};
        const auto [position, error] = std::from_chars(hop_number.data(), hop_number.data() + hop_number.size(), number);
        if (error != std::errc{} || position != hop_number.data() + hop_number.size()) continue;
        hops.push_back({number, address, classify_network_address(address)});
    }
    return hops;
}

std::vector<PathStabilityHop> parse_mtr_hops(const std::string& mtr_output) {
    std::vector<PathStabilityHop> hops;
    std::istringstream lines(mtr_output);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::string ordinal, address, loss;
        if (!(fields >> ordinal >> address >> loss)) continue;
        const auto dot = ordinal.find('.');
        if (dot == std::string::npos) continue;
        unsigned int number{};
        const auto [position, error] = std::from_chars(ordinal.data(), ordinal.data() + dot, number);
        if (error != std::errc{} || position != ordinal.data() + dot || loss.empty()) continue;
        char* end{};
        const double loss_percent = std::strtod(loss.c_str(), &end);
        const bool parsed_plain_number = end == loss.c_str() + loss.size();
        const bool parsed_percent = end == loss.c_str() + loss.size() - 1 && loss.back() == '%';
        if (!parsed_plain_number && !parsed_percent) continue;
        hops.push_back({number, address, classify_network_address(address), loss_percent});
    }
    return hops;
}
} // namespace ffc
