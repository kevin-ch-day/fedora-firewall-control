#include "ffc/network_diagnostics.hpp"

#include <algorithm>
#include <ranges>

namespace ffc {
namespace {
std::string output_or_error(const CommandResult& result) {
    if (!result.stdout_text.empty() && !result.stderr_text.empty()) return result.stdout_text + "\n" + result.stderr_text;
    return result.stdout_text.empty() ? result.stderr_text : result.stdout_text;
}
} // namespace

bool NetworkDiagnostics::has_unavailable_tools() const {
    const auto unavailable = [](const auto& item) { return !item.command_available; };
    return std::ranges::any_of(probes, unavailable) ||
           std::ranges::any_of(traceroutes, unavailable) ||
           (path_stability.has_value() && !path_stability->command_available) ||
           std::ranges::any_of(resolver_probes, unavailable);
}

NetworkDiagnostics ConnectivityAssessment::inspect(const bool extended, const bool advanced) const {
    NetworkDiagnostics diagnostics;
    for (const std::string destination : {"1.1.1.1", "8.8.8.8"}) {
        const auto result = runner_.run({"ping", "-n", "-c", "2", "-W", "2", destination});
        diagnostics.probes.push_back({destination, result.success(), result.exit_code != 127, output_or_error(result)});
    }

    std::vector<std::string> route_targets{"1.1.1.1"};
    if (extended || advanced) route_targets.insert(route_targets.end(), {"8.8.8.8", "9.9.9.9", "208.67.222.222"});
    for (const auto& destination : route_targets) {
        const auto route = runner_.run({"traceroute", "-n", "-m", "8", "-q", "1", "-w", "2", destination});
        const auto output = output_or_error(route);
        const auto hops = parse_traceroute_hops(output);
        const bool reached_destination = std::any_of(hops.begin(), hops.end(), [&destination](const TracerouteHop& hop) { return hop.address == destination; });
        diagnostics.traceroutes.push_back({destination, route.exit_code != 127, reached_destination, output, hops});
    }
    if (advanced) {
        constexpr const char* path_target = "1.1.1.1";
        const auto mtr = runner_.run({"mtr", "-n", "-r", "-c", "5", "-w", path_target});
        const auto output = output_or_error(mtr);
        const auto hops = parse_mtr_hops(output);
        const bool destination_observed = std::any_of(hops.begin(), hops.end(), [](const PathStabilityHop& hop) { return hop.address == path_target; });
        diagnostics.path_stability = PathStabilityReport{mtr.exit_code != 127, destination_observed, path_target, output, hops};

        for (const std::string resolver : {"1.1.1.1", "8.8.8.8", "9.9.9.9"}) {
            const auto dns = runner_.run({"dig", "@" + resolver, "example.com", "A", "+time=2", "+tries=1", "+stats", "+noall", "+answer", "+comments"});
            const auto dns_output = output_or_error(dns);
            diagnostics.resolver_probes.push_back({resolver, dns.exit_code != 127, dns.success() && dns_output.find("status: NOERROR") != std::string::npos, dns_output});
        }
    }
    return diagnostics;
}
} // namespace ffc
