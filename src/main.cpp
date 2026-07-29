#include "ffc/application.hpp"
#include "ffc/command_runner.hpp"
#include "ffc/firewalld_backend.hpp"
#include "ffc/network_manager.hpp"
#include "ffc/terminal_ui.hpp"
#include "ffc/vpn.hpp"
#include "ffc/socket_inspector.hpp"
#include "ffc/security_signals.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/credentials.hpp"
#include "ffc/operating_mode.hpp"
#include "ffc/posture_inspector.hpp"
#include "ffc/security_advisories.hpp"

int main(int argc, char** argv) {
    ffc::ProcessCommandRunner runner;
    ffc::FirewalldCommandBackend backend(runner);
    ffc::NetworkManagerInspector network_manager(runner);
    ffc::VpnInspector vpn(runner);
    ffc::SocketInspector sockets(runner);
    ffc::SecuritySignalsInspector security_signals(runner);
    ffc::IpifyCredentialStore ipify_credentials;
    ffc::NetworkMetadataInspector network_metadata(runner, ipify_credentials);
    ffc::NetworkHistoryStore network_history;
    ffc::NetworkEvidenceService network_evidence(network_metadata, network_history);
    ffc::NetworkDiagnosticsInspector network_diagnostics(runner);
    ffc::SecurityAdvisoryInspector security_advisories(runner);
    ffc::OperatingModeStore operating_mode;
    ffc::PostureInspector posture(backend, network_manager, vpn, sockets, security_signals, operating_mode);
    ffc::TerminalUi ui;
    ffc::Dashboard dashboard(ui);
    return ffc::Application(posture, network_evidence, network_diagnostics, security_advisories, ipify_credentials, operating_mode, dashboard).run(argc, argv);
}
