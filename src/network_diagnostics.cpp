#include "ffc/network_diagnostics.hpp"

namespace ffc {
namespace {
std::string output_or_error(const CommandResult& result) {
    if (!result.stdout_text.empty() && !result.stderr_text.empty()) return result.stdout_text + "\n" + result.stderr_text;
    return result.stdout_text.empty() ? result.stderr_text : result.stdout_text;
}
} // namespace

NetworkDiagnostics NetworkDiagnosticsInspector::inspect() const {
    NetworkDiagnostics diagnostics;
    for (const std::string destination : {"1.1.1.1", "8.8.8.8"}) {
        const auto result = runner_.run({"ping", "-n", "-c", "2", "-W", "2", destination});
        diagnostics.probes.push_back({destination, result.success(), result.exit_code != 127, output_or_error(result)});
    }

    const auto route = runner_.run({"traceroute", "-n", "-m", "8", "-q", "1", "-w", "2", "1.1.1.1"});
    diagnostics.traceroute_command_available = route.exit_code != 127;
    diagnostics.traceroute_completed = route.success();
    diagnostics.traceroute_output = output_or_error(route);
    return diagnostics;
}
} // namespace ffc
