#include "test_support.hpp"

#include "ffc/network_route.hpp"

#include <cmath>
#include <cstdint>
#include <string>

namespace ffc::test {
void run_network_path_tests() {
    const auto hops = parse_traceroute_hops(" 1  192.168.0.1  0.5 ms\n 2  100.93.189.130 14.2 ms\n 4  1.1.1.1 22.0 ms\n");
    expect(hops.size() == 3 && hops.front().scope == NetworkAddressScope::Private && hops.at(1).scope == NetworkAddressScope::CarrierGradeNat && hops.back().scope == NetworkAddressScope::Public, "classifies traceroute address scopes");
    expect(parse_traceroute_hops(" 0 1.1.1.1 1 ms\n -1 1.1.1.1 1 ms\n 3 \x1b[31m1.1.1.1 1 ms\n 4 8.8.8.8 1 ms\n").size() == 1, "rejects malformed traceroute fields");
    const auto mtr = parse_mtr_hops(" 1.|-- 192.168.0.1 0.0%\n 2.|-- 100.93.189.131 0.0%\n 3.|-- ??? 100.0\n11.|-- 1.1.1.1 0.0%\n");
    expect(mtr.size() == 4 && mtr.at(2).response_loss_percent == 100.0 && mtr.at(1).scope == NetworkAddressScope::CarrierGradeNat && parse_mtr_hops(" 1.|-- 192.168.0.1 nan%\n 2.|-- 1.1.1.1 0.0%\n").size() == 1, "parses MTR timeout and rejects invalid loss fields");
    expect(classify_network_address("198.51.100.25") == NetworkAddressScope::SpecialUse && classify_network_address("::ffff:192.168.1.20") == NetworkAddressScope::Private && classify_network_address("100.64.0.0") == NetworkAddressScope::CarrierGradeNat && classify_network_address("239.255.255.255") == NetworkAddressScope::Multicast, "handles special-use IPv4 and mapped IPv6 boundaries");
    bool invariants = true; std::uint32_t state = 0x7f4a7c15U;
    for (unsigned sample = 0; sample < 1000U; ++sample) { std::string noise; for (unsigned index = 0; index < (state % 257U) + 1U; ++index) { state = state * 1664525U + 1013904223U; noise.push_back(static_cast<char>(state)); } for (const auto& hop : parse_traceroute_hops(noise)) invariants = invariants && hop.number > 0U && hop.scope != NetworkAddressScope::Unknown; for (const auto& hop : parse_mtr_hops(noise)) invariants = invariants && hop.number > 0U && hop.response_loss_percent && std::isfinite(*hop.response_loss_percent) && *hop.response_loss_percent >= 0.0 && *hop.response_loss_percent <= 100.0; }
    expect(invariants && parse_traceroute_hops(std::string(65536U, '\x1b')).empty() && parse_mtr_hops(std::string(65536U, '\x1b')).empty(), "maintains network parser safety invariants under binary fuzz input");
}
} // namespace ffc::test
