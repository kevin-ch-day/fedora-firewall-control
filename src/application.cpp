#include "ffc/application.hpp"

#include "ffc/readiness.hpp"

#include <algorithm>
#include <iostream>
#include <termios.h>
#include <unistd.h>

namespace ffc {
namespace {
bool prompt_for_ipify_key(std::string& key, std::string& error) {
    if (!isatty(STDIN_FILENO)) { error = "standard input is not a terminal; run this command interactively"; return false; }

    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) != 0) { error = "could not read terminal settings"; return false; }
    termios hidden = original;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    std::cout << "Geo ipify API key (input hidden): " << std::flush;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) { error = "could not hide terminal input"; return false; }
    const bool read = static_cast<bool>(std::getline(std::cin, key));
    const bool restored = tcsetattr(STDIN_FILENO, TCSAFLUSH, &original) == 0;
    std::cout << '\n';
    if (!restored) { error = "could not restore terminal input"; return false; }
    if (!read) { error = "could not read API key"; return false; }
    return true;
}
} // namespace

Application::Application(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const SecurityAdvisoryInspector& security_advisories, const IpifyCredentialStore& ipify_credentials, OperatingModeStore& operating_mode, Dashboard& dashboard)
    : posture_(posture), network_evidence_(network_evidence), network_diagnostics_(network_diagnostics), security_advisories_(security_advisories), ipify_credentials_(ipify_credentials), operating_mode_(operating_mode), dashboard_(dashboard) {}

void Application::refresh() { state_ = posture_.inspect(); }

int Application::readiness_exit_code() const {
    bool warned = false;
    for (const auto& check : assess_readiness(state_)) {
        if (check.level == CheckLevel::Fail) return 2;
        if (check.level == CheckLevel::Warn) warned = true;
    }
    return warned ? 1 : 0;
}

void Application::print_usage() {
    std::cout << "Usage: ffc [--status | --readiness | --listeners | --network-diagnostics | --security-advisories | --network-metadata [--enrich] | --network-history | --configure-ipify-key | --mode [normal|hostile] | --help]\n\n"
              << "Without an option, opens the interactive read-only dashboard.\n"
              << "  --status     Print firewall posture and exposure summary.\n"
              << "  --readiness  Print readiness checks (exit: 0 pass, 1 warning, 2 fail).\n"
              << "  --listeners  Print non-loopback local listening sockets.\n"
              << "  --network-diagnostics  Run bounded ping and traceroute tests (external traffic).\n"
              << "  --security-advisories  Query available DNF5 security advisories and CVE references.\n"
              << "  --network-metadata [--enrich]  Query public-IP and save route metadata; enrichment uses one ipify credit.\n"
              << "  --network-history   Print locally saved public-IP and route metadata.\n"
              << "  --configure-ipify-key  Prompt for and securely save a Geo ipify API key.\n"
              << "  --mode [normal|hostile]  Show or set assessment-only operating mode.\n"
              << "  --help       Show this help.\n";
}

int Application::run_interactive() {
    std::string choice;
    do {
        dashboard_.show_menu(state_);
        if (!std::getline(std::cin, choice) || choice == "0") break;
        if (choice == "r" || choice == "R") { refresh(); continue; }
        if (choice == "m" || choice == "M") {
            const auto capture = network_evidence_.capture(false, !state_.vpn.active_tunnel_interfaces.empty());
            dashboard_.show_detail_header(); dashboard_.show_network_metadata(capture.metadata, capture.history_status()); dashboard_.pause(); continue;
        }
        if (choice == "h" || choice == "H") {
            const auto history = network_evidence_.read_history();
            dashboard_.show_detail_header(); dashboard_.show_network_history(history.records, history.display_status()); dashboard_.pause(); continue;
        }
        if (choice == "d" || choice == "D") {
            dashboard_.show_detail_header(); dashboard_.show_network_diagnostics(network_diagnostics_.inspect()); dashboard_.pause(); continue;
        }
        if (choice == "s" || choice == "S") {
            dashboard_.show_detail_header(); dashboard_.show_security_advisories(security_advisories_.inspect()); dashboard_.pause(); continue;
        }
        dashboard_.show_detail_header();
        if (choice == "1") dashboard_.show_status(state_);
        else if (choice == "2") dashboard_.show_zones(state_, "Zones", ZoneView::All);
        else if (choice == "3") dashboard_.show_zones(state_, "Interfaces and zone assignments", ZoneView::Interfaces);
        else if (choice == "4") dashboard_.show_zones(state_, "Allowed services", ZoneView::Services);
        else if (choice == "5") dashboard_.show_zones(state_, "Explicit open ports", ZoneView::Ports);
        else if (choice == "6") dashboard_.show_zones(state_, "Rich rules", ZoneView::RichRules);
        else if (choice == "7") dashboard_.show_zones(state_, "Forwarding and masquerading", ZoneView::Routing);
        else if (choice == "8") dashboard_.show_zones(state_, "Runtime/permanent differences", ZoneView::Drift);
        else if (choice == "9") dashboard_.show_readiness(state_);
        else if (choice == "l" || choice == "L") dashboard_.show_listeners(state_);
        else dashboard_.show_invalid_selection();
        dashboard_.pause();
    } while (true);
    dashboard_.show_goodbye();
    return 0;
}

int Application::run(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--configure-ipify-key") {
        std::string key;
        std::string result;
        if (!prompt_for_ipify_key(key, result)) { std::cerr << "Could not configure Geo ipify key: " << result << '\n'; return 2; }
        if (!ipify_credentials_.save(key, result)) { std::cerr << "Could not save Geo ipify key: " << result << '\n'; return 2; }
        std::cout << "Geo ipify API key saved to " << result << " with owner-only permissions.\n";
        return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--mode") {
        OperatingMode mode; if (!parse_operating_mode(argv[2], mode)) { print_usage(); return 2; }
        std::string result; if (!operating_mode_.save(mode, result)) { std::cerr << "Could not save mode: " << result << '\n'; return 2; }
        std::cout << "Assessment mode set to " << to_string(mode) << ". Firewall settings were not changed.\n";
        return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--network-metadata" && std::string(argv[2]) == "--enrich") {
        refresh(); const auto capture = network_evidence_.capture(true, !state_.vpn.active_tunnel_interfaces.empty());
        dashboard_.show_network_metadata(capture.metadata, capture.history_status()); return capture.successful() ? 0 : 2;
    }
    if (argc > 2) { print_usage(); return 2; }
    if (argc == 2 && std::string(argv[1]) == "--help") { print_usage(); return 0; }
    if (argc == 2 && std::string(argv[1]) == "--mode") { std::cout << "Assessment mode: " << to_string(operating_mode_.load()) << '\n'; return 0; }
    if (argc == 2 && std::string(argv[1]) != "--status" && std::string(argv[1]) != "--readiness" && std::string(argv[1]) != "--listeners" && std::string(argv[1]) != "--network-diagnostics" && std::string(argv[1]) != "--security-advisories" && std::string(argv[1]) != "--network-metadata" && std::string(argv[1]) != "--network-history") { print_usage(); return 2; }
    if (argc == 2 && std::string(argv[1]) == "--network-diagnostics") {
        const auto diagnostics = network_diagnostics_.inspect(); dashboard_.show_network_diagnostics(diagnostics);
        const bool all_commands_available = diagnostics.traceroute_command_available && std::all_of(diagnostics.probes.begin(), diagnostics.probes.end(), [](const ReachabilityProbe& probe) { return probe.command_available; });
        return all_commands_available ? 0 : 2;
    }
    if (argc == 2 && std::string(argv[1]) == "--security-advisories") {
        const auto report = security_advisories_.inspect(); dashboard_.show_security_advisories(report);
        return report.query_succeeded ? 0 : 2;
    }
    refresh();
    if (argc == 2 && std::string(argv[1]) == "--status") { dashboard_.show_status(state_); dashboard_.show_overview(state_); return state_.installed ? 0 : 2; }
    if (argc == 2 && std::string(argv[1]) == "--readiness") { dashboard_.show_readiness(state_); return readiness_exit_code(); }
    if (argc == 2 && std::string(argv[1]) == "--listeners") { dashboard_.show_listeners(state_); return state_.sockets.available ? 0 : 2; }
    if (argc == 2 && std::string(argv[1]) == "--network-metadata") {
        const auto capture = network_evidence_.capture(false, !state_.vpn.active_tunnel_interfaces.empty());
        dashboard_.show_network_metadata(capture.metadata, capture.history_status()); return capture.successful() ? 0 : 2;
    }
    if (argc == 2 && std::string(argv[1]) == "--network-history") {
        const auto history = network_evidence_.read_history();
        dashboard_.show_network_history(history.records, history.display_status()); return history.available ? 0 : 2;
    }
    return run_interactive();
}
} // namespace ffc
