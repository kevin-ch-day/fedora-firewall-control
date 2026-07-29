#include "ffc/network_route.hpp"

#include <charconv>
#include <cmath>
#include <cstdlib>
#include <sstream>

namespace ffc {
namespace {
bool is_decimal_loss_field(const std::string& loss) {
    const auto end = loss.back() == '%' ? loss.size() - 1 : loss.size();
    if (end == 0) return false;
    bool decimal_point_seen = false;
    for (std::size_t index = 0; index < end; ++index) {
        const unsigned char character = static_cast<unsigned char>(loss[index]);
        if (character >= '0' && character <= '9') continue;
        if (character == '.' && !decimal_point_seen) { decimal_point_seen = true; continue; }
        return false;
    }
    return true;
}
} // namespace

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
        if (error != std::errc{} || position != hop_number.data() + hop_number.size() || number == 0U) continue;
        const auto scope = classify_network_address(address);
        if (scope == NetworkAddressScope::Unknown) continue;
        hops.push_back({number, address, scope});
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
        if (error != std::errc{} || position != ordinal.data() + dot || number == 0U || loss.empty() || !is_decimal_loss_field(loss)) continue;
        char* end{};
        const double loss_percent = std::strtod(loss.c_str(), &end);
        const bool parsed_plain_number = end == loss.c_str() + loss.size();
        const bool parsed_percent = end == loss.c_str() + loss.size() - 1 && loss.back() == '%';
        if ((!parsed_plain_number && !parsed_percent) || !std::isfinite(loss_percent) || loss_percent < 0.0 || loss_percent > 100.0) continue;
        const auto scope = classify_network_address(address);
        if ((address == "???" && loss_percent != 100.0) || (address != "???" && scope == NetworkAddressScope::Unknown)) continue;
        hops.push_back({number, address, scope, loss_percent});
    }
    return hops;
}
} // namespace ffc
