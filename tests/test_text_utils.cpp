#include "test_support.hpp"

#include "ffc/network_diagnostics.hpp"
#include "ffc/text_utils.hpp"

namespace ffc::test {
void run_text_utils_tests() {
    expect(trim_copy(" \t defensive input \n") == "defensive input", "trims surrounding ASCII whitespace without changing content");
    expect(lowercase_copy("DEFCON-42") == "defcon-42", "lowercases ASCII command text");
    expect(normalize_command("  ReFrEsH \n") == "refresh", "normalizes interactive command aliases");

    NetworkDiagnostics diagnostics;
    diagnostics.probes.push_back({"1.1.1.1", false, false, {}});
    expect(diagnostics.has_unavailable_tools(), "reports unavailable diagnostic tooling from its own value state");
    diagnostics.probes.front().command_available = true;
    diagnostics.path_stability = PathStabilityReport{false, false, {}, {}, {}};
    expect(diagnostics.has_unavailable_tools(), "includes optional path-stability tooling in the availability result");
}
} // namespace ffc::test
