#pragma once

#include <optional>
#include <string>
#include <vector>

namespace ffc {
// Address scope is descriptive route context only. It does not establish the
// owner, physical location, or trust level of a network.
enum class NetworkAddressScope { Private, CarrierGradeNat, LinkLocal, Loopback, Multicast, Public, Unknown };

struct TracerouteHop {
    unsigned int number{0};
    std::string address;
    NetworkAddressScope scope{NetworkAddressScope::Unknown};
};

struct PathStabilityHop {
    unsigned int number{0};
    std::string address;
    NetworkAddressScope scope{NetworkAddressScope::Unknown};
    std::optional<double> response_loss_percent;
};

[[nodiscard]] NetworkAddressScope classify_network_address(const std::string& address);
[[nodiscard]] std::string network_address_scope_label(NetworkAddressScope scope);
[[nodiscard]] std::vector<TracerouteHop> parse_traceroute_hops(const std::string& traceroute_output);
[[nodiscard]] std::vector<PathStabilityHop> parse_mtr_hops(const std::string& mtr_output);
} // namespace ffc
