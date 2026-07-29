#pragma once

#include "ffc/command_runner.hpp"
#include "ffc/network_route.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ffc {
struct ReachabilityProbe {
    std::string destination;
    bool reachable{false};
    bool command_available{true};
    std::string output;
};

struct TracerouteResult {
    std::string destination;
    bool command_available{true};
    bool completed{false};
    std::string output;
    std::vector<TracerouteHop> hops;
};

struct PathStabilityReport {
    bool command_available{true};
    bool destination_observed{false};
    std::string destination;
    std::string output;
    std::vector<PathStabilityHop> hops;
};

struct ResolverProbe {
    std::string resolver;
    bool command_available{true};
    bool answered{false};
    std::string output;
};

// These active checks are intentionally bounded and run only when explicitly
// requested. A missing reply is diagnostic data, not proof of interference.
struct NetworkDiagnostics {
    std::vector<ReachabilityProbe> probes;
    std::vector<TracerouteResult> traceroutes;
    std::optional<PathStabilityReport> path_stability;
    std::vector<ResolverProbe> resolver_probes;

    [[nodiscard]] bool has_unavailable_tools() const;
};

class ConnectivityAssessment {
public:
    explicit ConnectivityAssessment(const CommandRunner& runner) : runner_(runner) {}
    // Extended mode adds three public-resolver traceroutes. Advanced mode adds
    // five MTR samples to one resolver and three direct DNS checks, and implies
    // extended mode. Both are opt-in because they generate diagnostic traffic.
    [[nodiscard]] NetworkDiagnostics inspect(bool extended = false, bool advanced = false) const;

private:
    const CommandRunner& runner_;
};
using NetworkDiagnosticsInspector = ConnectivityAssessment; // Compatibility name for early integrations.
} // namespace ffc
