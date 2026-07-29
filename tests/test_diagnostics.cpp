#include "test_support.hpp"

#include "ffc/network_diagnostics.hpp"

namespace ffc::test {
void run_diagnostics_tests() {
    SequencedCommandRunner basic({{0, "first", {}}, {0, "second", {}}, {0, " 1 1.1.1.1 10 ms\n", {}}});
    const auto basic_report = ConnectivityAssessment(basic).inspect();
    expect(basic_report.probes.size() == 2 && basic_report.traceroutes.front().completed && basic.calls.size() == 3 && basic.calls.at(2).front() == "traceroute", "runs the bounded basic diagnostics plan");
    SequencedCommandRunner partial({{0, "first", {}}, {0, "second", {}}, {0, " 1 192.168.0.1 1 ms\n", "route did not reach target"}});
    expect(!ConnectivityAssessment(partial).inspect().traceroutes.front().completed, "does not mistake a successful traceroute process for a completed route");
    SequencedCommandRunner advanced({{0, "first", {}}, {0, "second", {}}, {0, " 1 1.1.1.1 10 ms\n", {}}, {0, " 1 8.8.8.8 10 ms\n", {}}, {0, " 1 9.9.9.9 10 ms\n", {}}, {0, " 1 208.67.222.222 10 ms\n", {}}, {0, " 1.|-- 1.1.1.1 0.0%\n", {}}, {0, "status: NOERROR", {}}, {0, "status: NOERROR", {}}, {0, "status: NOERROR", {}}});
    const auto advanced_report = ConnectivityAssessment(advanced).inspect(false, true);
    expect(advanced_report.traceroutes.size() == 4 && advanced_report.path_stability && advanced_report.path_stability->destination_observed && advanced_report.resolver_probes.size() == 3 && advanced.calls.size() == 10, "runs advanced diagnostics only when explicitly requested");
    SequencedCommandRunner unavailable({{127, {}, "ping unavailable"}, {127, {}, "ping unavailable"}, {127, {}, "traceroute unavailable"}});
    const auto unavailable_report = ConnectivityAssessment(unavailable).inspect();
    expect(!unavailable_report.probes.front().command_available && !unavailable_report.traceroutes.front().command_available, "distinguishes unavailable tools from hostile-network evidence");
}
} // namespace ffc::test
