#include "test_support.hpp"

#include "ffc/command_executor.hpp"
#include "ffc/credentials.hpp"
#include "ffc/evidence_quality.hpp"
#include "ffc/firewall_backend.hpp"
#include "ffc/log_analysis.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/network_history.hpp"
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

class RoutingCommandRunner final : public CommandRunner {
public:
    CommandResult run(const std::vector<std::string>& arguments) const override {
        if (arguments.empty())
            return {-1, {}, "missing command"};
        if (arguments.front() == "rpm")
            return {1, {}, {}};
        if (arguments.front() == "ip" || arguments.front() == "ss")
            return {0, {}, {}};
        if (arguments.front() == "journalctl")
            return {0, "-- No entries --\n", {}};
        if (arguments.front() == "nmcli")
            return {0, "enp1s0:ethernet:connected\n", {}};
        if (arguments.front() == "timedatectl")
            return {0, "yes\n", {}};
        if (arguments.front() == "systemctl")
            return {3, "inactive\n", "journald inactive"};
        return {-1, {}, "unexpected command"};
    }
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

    const RoutingCommandRunner routing_runner;
    const NetworkManagerInspector checked_network_manager(routing_runner);
    const VpnInspector checked_vpn(routing_runner);
    const SocketInspector checked_sockets(routing_runner);
    const SecuritySignalsInspector checked_security_signals(routing_runner);
    const EvidenceQualityInspector checked_evidence_quality(routing_runner);
    const DefensivePostureCollector checked_posture(
        firewall, checked_network_manager, checked_vpn, checked_sockets, checked_security_signals,
        checked_evidence_quality, operating_mode);
    const auto cross_checked = checked_posture.inspect();
    expect(cross_checked.security_signals.kernel_journal_status == JournalQueryStatus::Partial &&
               cross_checked.security_signals.firewalld_journal_status == JournalQueryStatus::Partial &&
               !cross_checked.security_signals.kernel_journal_available &&
               !cross_checked.security_signals.firewalld_journal_available,
           "downgrades otherwise successful journal samples when journald service health is not confirmed");
}
} // namespace ffc::test
