#pragma once

#include "ffc/command_runner.hpp"

#include <string>
#include <vector>

namespace ffc {
struct ReachabilityProbe {
    std::string destination;
    bool reachable{false};
    bool command_available{true};
    std::string output;
};

// These active checks are intentionally bounded and run only when explicitly
// requested. A missing reply is diagnostic data, not proof of interference.
struct NetworkDiagnostics {
    std::vector<ReachabilityProbe> probes;
    bool traceroute_command_available{true};
    bool traceroute_completed{false};
    std::string traceroute_output;
};

class ConnectivityAssessment {
public:
    explicit ConnectivityAssessment(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] NetworkDiagnostics inspect() const;

private:
    const CommandRunner& runner_;
};
using NetworkDiagnosticsInspector = ConnectivityAssessment; // Compatibility name for early integrations.
} // namespace ffc
