#include "test_support.hpp"

#include "ffc/command_executor.hpp"
#include "ffc/credentials.hpp"
#include "ffc/evidence_quality.hpp"
#include "ffc/firewall_backend.hpp"
#include "ffc/log_analysis.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/operating_mode.hpp"
#include "ffc/posture_inspector.hpp"
#include "ffc/security_advisories.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/terminal_ui.hpp"
#include "ffc/vpn.hpp"

namespace ffc::test {
namespace {
class CountingFirewallBackend final : public FirewallBackend {
public:
    [[nodiscard]] FirewallState inspect(const PostureCollectionDepth depth) const override {
        ++inspect_calls;
        last_depth = depth;
        return {};
    }

    mutable unsigned inspect_calls{0};
    mutable PostureCollectionDepth last_depth{PostureCollectionDepth::Complete};
};
}

void run_command_executor_tests() {
    const StubCommandRunner runner({0, {}, {}});
    CountingFirewallBackend firewall;
    const NetworkManagerInspector network_manager(runner);
    const VpnInspector vpn(runner);
    const SocketInspector sockets(runner);
    const SecuritySignalsInspector security_signals(runner);
    const EvidenceQualityInspector evidence_quality(runner);
    OperatingModeStore operating_mode;
    const DefensivePostureCollector posture(firewall, network_manager, vpn, sockets, security_signals, evidence_quality, operating_mode);
    const IpifyCredentialStore credentials;
    const NetworkMetadataInspector metadata(runner, credentials);
    const NetworkHistoryStore history;
    const NetworkEvidenceRecorder evidence(metadata, history);
    const ConnectivityAssessment diagnostics(runner);
    const VulnerabilityAdvisoryCollector advisories(runner);
    const LocalLogAnalyzer log_analyzer;
    TerminalUi ui;
    OperationsDashboard dashboard(ui);
    const CommandExecutor executor(posture, vpn, sockets, evidence, diagnostics, advisories, log_analyzer, credentials, operating_mode, dashboard);

    const auto landing = posture.inspect(PostureCollectionDepth::Landing);
    (void)landing;
    expect(firewall.inspect_calls == 1U && firewall.last_depth == PostureCollectionDepth::Landing, "collects the dashboard landing snapshot at the lightweight depth");

    CommandLine listeners;
    listeners.action = CommandAction::Listeners;
    expect(executor.execute(listeners) == 0 && firewall.inspect_calls == 1U, "runs listener-only commands without collecting firewall posture");

    CommandLine history_command;
    history_command.action = CommandAction::NetworkHistory;
    const auto ignored_result = executor.execute(history_command);
    (void)ignored_result;
    expect(firewall.inspect_calls == 1U, "reads saved network history without collecting firewall posture");
}
} // namespace ffc::test
