#include "network_diagnostics_renderer.hpp"

#include <algorithm>
#include <iostream>

namespace ffc {
void render_network_diagnostics(TerminalUi& ui, const NetworkDiagnostics& diagnostics) {
    ui.section("Network reachability probes");
    std::cout << "  " << ui.muted("Two ICMP echo requests are sent to each public resolver.") << '\n';
    for (const auto& probe : diagnostics.probes) {
        const std::string result = !probe.command_available ? ui.danger("PING UNAVAILABLE") : probe.reachable ? ui.success("REACHABLE") : ui.warning("NO REPLY");
        std::cout << "  " << result << "  " << ui.accent(probe.destination) << '\n';
        if (!probe.output.empty()) std::cout << "    " << probe.output;
        if (!probe.output.empty() && probe.output.back() != '\n') std::cout << '\n';
    }

    for (const auto& trace : diagnostics.traceroutes) {
        ui.section("Traceroute to " + trace.destination);
        std::cout << "  " << ui.muted("Numeric addresses only; one query per hop; maximum 8 hops.") << '\n';
        if (!trace.command_available) {
            std::cout << "  " << ui.danger("traceroute is not installed. Run scripts/setup-firewall-dev.sh to install it.") << '\n';
        } else if (trace.output.empty()) {
            std::cout << "  " << ui.warning("Traceroute produced no output.") << '\n';
        } else {
            std::cout << trace.output;
            if (trace.output.back() != '\n') std::cout << '\n';
            if (!trace.hops.empty()) {
                ui.section("Route scope interpretation");
                for (const auto& hop : trace.hops) {
                    std::cout << "  " << ui.accent("hop " + std::to_string(hop.number)) << "  " << hop.address
                              << ui.muted(" — " + network_address_scope_label(hop.scope)) << '\n';
                }
            }
            if (!trace.completed) std::cout << "  " << ui.muted("Target not observed before the 8-hop cap; this can be normal routing or probe filtering.") << '\n';
        }
    }

    if (diagnostics.path_stability) {
        const auto& report = *diagnostics.path_stability;
        ui.section("Path stability to " + report.destination);
        std::cout << "  " << ui.muted("Five MTR samples; this measures router replies, not an attack or venue identity.") << '\n';
        if (!report.command_available) {
            std::cout << "  " << ui.danger("mtr is not installed. Install the optional diagnostics tools to enable this check.") << '\n';
        } else if (report.output.empty()) {
            std::cout << "  " << ui.warning("MTR produced no output.") << '\n';
        } else {
            std::cout << report.output;
            if (report.output.back() != '\n') std::cout << '\n';
            const auto destination = std::find_if(report.hops.begin(), report.hops.end(), [&report](const PathStabilityHop& hop) { return hop.address == report.destination; });
            const bool intermediate_loss = std::any_of(report.hops.begin(), report.hops.end(), [&report](const PathStabilityHop& hop) { return hop.address != report.destination && hop.response_loss_percent && *hop.response_loss_percent > 0.0; });
            if (!report.destination_observed || destination == report.hops.end()) {
                std::cout << "  " << ui.muted("Destination did not appear in the MTR report; endpoint loss cannot be assessed from this run.") << '\n';
            } else if (destination->response_loss_percent && *destination->response_loss_percent == 0.0 && intermediate_loss) {
                std::cout << "  " << ui.success("ENDPOINT 0% LOSS") << "  " << ui.muted("Intermediate reply loss is likely ICMP rate limiting/de-prioritization, not end-to-end loss.") << '\n';
            } else if (destination->response_loss_percent) {
                std::cout << "  " << ui.accent("Endpoint response loss: " + std::to_string(*destination->response_loss_percent) + "%") << '\n';
                std::cout << "  " << ui.muted("Repeat from the same network and correlate with application failures before treating this as path loss.") << '\n';
            }
        }
    }

    if (!diagnostics.resolver_probes.empty()) {
        ui.section("Direct DNS resolver checks");
        std::cout << "  " << ui.muted("One UDP DNS query for example.com is sent to each resolver; resolvers receive the query and source address.") << '\n';
        for (const auto& probe : diagnostics.resolver_probes) {
            const std::string state = !probe.command_available ? ui.danger("DIG UNAVAILABLE") : probe.answered ? ui.success("ANSWERED") : ui.warning("NO USABLE ANSWER");
            std::cout << "  " << state << "  " << ui.accent(probe.resolver) << '\n';
            if (!probe.output.empty()) {
                std::cout << "    " << probe.output;
                if (probe.output.back() != '\n') std::cout << '\n';
            }
        }
    }
    std::cout << "\n  " << ui.muted("Run only when you intend to generate diagnostic traffic; results do not identify an attacker or network type.") << '\n';
}
} // namespace ffc
