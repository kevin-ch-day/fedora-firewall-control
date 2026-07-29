#include "ffc/command_executor.hpp"

#include "ffc/readiness.hpp"

#include <algorithm>
#include <iostream>
#include <termios.h>
#include <unistd.h>

namespace ffc {
namespace {
void print_usage() {
    std::cout << "Usage: ffc [--status | --readiness | --listeners | --threat-assessment | --network-diagnostics [--extended|--advanced] | --security-advisories | --network-metadata [--enrich] | --network-history | --log-analysis | --configure-ipify-key | --mode [normal|hostile] | --help]\n\n"
              << "Without an option, opens the interactive read-only dashboard.\n"
              << "  --status     Print firewall posture and exposure summary.\n"
              << "  --readiness  Print readiness checks (exit: 0 pass, 1 warning, 2 fail).\n"
              << "  --listeners  Print non-loopback local listening sockets.\n"
              << "  --threat-assessment  Review local evidence, exposure, and telemetry gaps; no attack verdicts.\n"
              << "  --network-diagnostics [--extended|--advanced]  Run bounded external tests; extended compares four routes, advanced also adds MTR and direct DNS checks.\n"
              << "  --security-advisories  Query available DNF5 security advisories and CVE references.\n"
              << "  --network-metadata [--enrich]  Query public-IP and save route metadata; enrichment uses one ipify credit.\n"
              << "  --network-history   Print locally saved public-IP and route metadata.\n"
              << "  --log-analysis      Summarize retained local ffc log activity and repeated errors.\n"
              << "  --configure-ipify-key  Prompt for and securely save a Geo ipify API key.\n"
              << "  --mode [normal|hostile]  Show or set assessment-only operating mode.\n"
              << "  --help       Show this help.\n";
    std::cout << "\nOwner-only application logs are stored under $XDG_STATE_HOME/fedora-firewall-control/\n"
              << "(or ~/.local/state/fedora-firewall-control/): operations.log, audit.log, security.log, and error.log.\n";
}
bool prompt_for_ipify_key(std::string& key, std::string& error) {
    if (!isatty(STDIN_FILENO)) { error = "standard input is not a terminal; run this command interactively"; return false; }
    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) != 0) { error = "could not read terminal settings"; return false; }
    termios hidden = original; hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    std::cout << "Geo ipify API key (input hidden): " << std::flush;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) { error = "could not hide terminal input"; return false; }
    const bool read = static_cast<bool>(std::getline(std::cin, key));
    const bool restored = tcsetattr(STDIN_FILENO, TCSAFLUSH, &original) == 0;
    std::cout << '\n';
    if (!restored) { error = "could not restore terminal input"; return false; }
    if (!read) { error = "could not read API key"; return false; }
    return true;
}
int readiness_exit_code(const FirewallState& state) {
    bool warned = false;
    for (const auto& check : assess_readiness(state)) { if (check.level == CheckLevel::Fail) return 2; if (check.level == CheckLevel::Warn) warned = true; }
    return warned ? 1 : 0;
}
} // namespace

CommandExecutor::CommandExecutor(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const SecurityAdvisoryInspector& security_advisories, const LocalLogAnalyzer& log_analyzer, const IpifyCredentialStore& ipify_credentials, OperatingModeStore& operating_mode, Dashboard& dashboard)
    : posture_(posture), network_evidence_(network_evidence), network_diagnostics_(network_diagnostics), security_advisories_(security_advisories), log_analyzer_(log_analyzer), ipify_credentials_(ipify_credentials), operating_mode_(operating_mode), dashboard_(dashboard) {}

int CommandExecutor::execute(const CommandLine& command) const {
    if (command.action == CommandAction::Invalid) { print_usage(); return 2; }
    if (command.action == CommandAction::Help) { print_usage(); return 0; }
    if (command.action == CommandAction::ConfigureIpifyKey) {
        std::string key, result;
        if (!prompt_for_ipify_key(key, result)) { std::cerr << "Could not configure Geo ipify key: " << result << '\n'; return 2; }
        if (!ipify_credentials_.save(key, result)) { std::cerr << "Could not save Geo ipify key: " << result << '\n'; return 2; }
        std::cout << "Geo ipify API key saved to " << result << " with owner-only permissions.\n"; return 0;
    }
    if (command.action == CommandAction::Mode) {
        if (!command.mode_to_set.has_value()) { std::cout << "Assessment mode: " << to_string(operating_mode_.load()) << '\n'; return 0; }
        std::string result; if (!operating_mode_.save(*command.mode_to_set, result)) { std::cerr << "Could not save mode: " << result << '\n'; return 2; }
        std::cout << "Assessment mode set to " << to_string(*command.mode_to_set) << ". Firewall settings were not changed.\n"; return 0;
    }
    if (command.action == CommandAction::NetworkDiagnostics) {
        const auto diagnostics = network_diagnostics_.inspect(command.extended_diagnostics, command.advanced_diagnostics); dashboard_.show_network_diagnostics(diagnostics);
        const bool available = std::all_of(diagnostics.traceroutes.begin(), diagnostics.traceroutes.end(), [](const TracerouteResult& trace) { return trace.command_available; }) && std::all_of(diagnostics.probes.begin(), diagnostics.probes.end(), [](const ReachabilityProbe& probe) { return probe.command_available; });
        const bool advanced_available = (!diagnostics.path_stability || diagnostics.path_stability->command_available) && std::all_of(diagnostics.resolver_probes.begin(), diagnostics.resolver_probes.end(), [](const ResolverProbe& probe) { return probe.command_available; });
        return available && advanced_available ? 0 : 2;
    }
    if (command.action == CommandAction::SecurityAdvisories) { const auto report = security_advisories_.inspect(); dashboard_.show_security_advisories(report); return report.query_succeeded ? 0 : 2; }
    if (command.action == CommandAction::LogAnalysis) { const auto analysis = log_analyzer_.inspect(); dashboard_.show_log_analysis(analysis); return analysis.logs_available ? 0 : 2; }

    const auto state = posture_.inspect();
    if (command.action == CommandAction::Status) { dashboard_.show_status(state); dashboard_.show_overview(state); return state.installed ? 0 : 2; }
    if (command.action == CommandAction::Readiness) { dashboard_.show_readiness(state); return readiness_exit_code(state); }
    if (command.action == CommandAction::Listeners) { dashboard_.show_listeners(state); return state.sockets.available ? 0 : 2; }
    if (command.action == CommandAction::ThreatAssessment) { dashboard_.show_threat_assessment(state); return 0; }
    if (command.action == CommandAction::NetworkMetadata) {
        const auto capture = network_evidence_.capture(command.enrich_metadata, !state.vpn.active_tunnel_interfaces.empty());
        dashboard_.show_network_metadata(capture.metadata, capture.history_status()); return capture.successful() ? 0 : 2;
    }
    if (command.action == CommandAction::NetworkHistory) { const auto history = network_evidence_.read_history(); dashboard_.show_network_history(history.records, history.display_status()); return history.available ? 0 : 2; }
    return 2;
}
} // namespace ffc
