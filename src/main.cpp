#include "ffc/application.hpp"
#include "ffc/command_runner.hpp"
#include "ffc/firewalld_backend.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/terminal_ui.hpp"
#include "ffc/vpn.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/evidence_quality.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/network_history.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/credentials.hpp"
#include "ffc/operating_mode.hpp"
#include "ffc/posture_inspector.hpp"
#include "ffc/security_advisories.hpp"
#include "ffc/command_executor.hpp"
#include "ffc/interactive_session.hpp"
#include "ffc/logging_engine.hpp"
#include "ffc/log_analysis.hpp"

int main(int argc, char** argv) {
    ffc::ProcessCommandRunner runner;
    ffc::FirewalldCommandBackend backend(runner);
    ffc::NetworkManagerInspector network_manager(runner);
    ffc::VpnInspector vpn(runner);
    ffc::SocketInspector sockets(runner);
    ffc::SecuritySignalsInspector security_signals(runner);
    ffc::EvidenceQualityInspector evidence_quality(runner);
    ffc::IpifyCredentialStore ipify_credentials;
    ffc::NetworkMetadataInspector network_metadata(runner, ipify_credentials);
    ffc::NetworkHistoryStore network_history;
    ffc::NetworkEvidenceRecorder network_evidence(network_metadata, network_history);
    ffc::ConnectivityAssessment network_diagnostics(runner);
    ffc::VulnerabilityAdvisoryCollector security_advisories(runner);
    ffc::OperatingModeStore operating_mode;
    ffc::LoggingEngine logger;
    ffc::LocalLogAnalyzer log_analyzer;
    ffc::DefensivePostureCollector posture(backend, network_manager, vpn, sockets, security_signals, evidence_quality, operating_mode);
    ffc::TerminalUi ui;
    ffc::OperationsDashboard dashboard(ui);
    ffc::CommandExecutor commands(posture, vpn, sockets, network_evidence, network_diagnostics, security_advisories, log_analyzer, ipify_credentials, operating_mode, dashboard);
    ffc::InteractiveSession interactive(posture, network_evidence, network_diagnostics, security_advisories, log_analyzer, dashboard, logger);
    return ffc::OperationsConsole(commands, interactive, logger).run(argc, argv);
}
