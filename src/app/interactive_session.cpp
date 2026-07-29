#include "ffc/interactive_session.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>

namespace ffc {
namespace {
std::string normalize_choice(std::string choice) {
    const auto first = std::find_if_not(choice.begin(), choice.end(), [](unsigned char character) { return std::isspace(character); });
    const auto last = std::find_if_not(choice.rbegin(), choice.rend(), [](unsigned char character) { return std::isspace(character); }).base();
    choice = first < last ? std::string(first, last) : std::string{};
    std::transform(choice.begin(), choice.end(), choice.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return choice;
}
}
InteractiveSession::InteractiveSession(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const SecurityAdvisoryInspector& security_advisories, const LocalLogAnalyzer& log_analyzer, Dashboard& dashboard, const LoggingEngine& logger)
    : posture_(posture), network_evidence_(network_evidence), network_diagnostics_(network_diagnostics), security_advisories_(security_advisories), log_analyzer_(log_analyzer), dashboard_(dashboard), logger_(logger) {}

void InteractiveSession::record_action(const char* action, LogChannel channel) const {
    logger_.record({channel, LogLevel::Info, "interactive-action", std::string("action=") + action});
}

void InteractiveSession::refresh() {
    logger_.record({LogChannel::Operations, LogLevel::Info, "posture-refresh", "source=interactive"});
    state_ = posture_.inspect();
}

int InteractiveSession::run() {
    logger_.record({LogChannel::Audit, LogLevel::Info, "interactive-session-start", {}});
    refresh(); std::string choice; DashboardMenu menu = DashboardMenu::Main;
    do {
        dashboard_.show_menu(state_, menu);
        if (!std::getline(std::cin, choice)) break;
        choice = normalize_choice(std::move(choice));
        if (choice == "0" || choice == "q" || choice == "quit" || choice == "exit") break;
        if (choice == "h" || choice == "help") { dashboard_.show_navigation_help(menu); dashboard_.pause(menu); continue; }
        if (choice == "r" || choice == "refresh") { record_action("refresh"); refresh(); continue; }
        if (menu == DashboardMenu::Main) {
            if (choice == "1" || choice == "f" || choice == "firewall") { menu = DashboardMenu::Firewall; continue; }
            if (choice == "2" || choice == "n" || choice == "network") { menu = DashboardMenu::Network; continue; }
            if (choice == "3" || choice == "s" || choice == "security") { menu = DashboardMenu::Security; continue; }
            logger_.record({LogChannel::Audit, LogLevel::Warning, "invalid-interactive-selection", {}}); dashboard_.show_invalid_selection(); dashboard_.pause(menu); continue;
        }
        if (choice == "b" || choice == "back") { menu = DashboardMenu::Main; continue; }
        if (menu == DashboardMenu::Firewall) {
            if (choice == "1") { record_action("status"); dashboard_.show_detail_header("Firewall service state"); dashboard_.show_status(state_); }
            else if (choice == "2") { record_action("zones"); dashboard_.show_detail_header("Default and active zones"); dashboard_.show_zones(state_, "Zones", ZoneView::All); }
            else if (choice == "3") { record_action("interfaces"); dashboard_.show_detail_header("Interfaces and zone assignments"); dashboard_.show_zones(state_, "Interfaces and zone assignments", ZoneView::Interfaces); }
            else if (choice == "4") { record_action("services"); dashboard_.show_detail_header("Allowed services"); dashboard_.show_zones(state_, "Allowed services", ZoneView::Services); }
            else if (choice == "5") { record_action("ports"); dashboard_.show_detail_header("Explicit open ports"); dashboard_.show_zones(state_, "Explicit open ports", ZoneView::Ports); }
            else if (choice == "6") { record_action("rich-rules"); dashboard_.show_detail_header("Rich rules"); dashboard_.show_zones(state_, "Rich rules", ZoneView::RichRules); }
            else if (choice == "7") { record_action("routing"); dashboard_.show_detail_header("Intra-zone forwarding and NAT"); dashboard_.show_zones(state_, "Intra-zone forwarding and masquerading", ZoneView::Routing); }
            else if (choice == "8") { record_action("configuration-drift", LogChannel::Security); dashboard_.show_detail_header("Runtime and permanent differences"); dashboard_.show_zones(state_, "Runtime/permanent differences", ZoneView::Drift); }
            else if (choice == "a" || choice == "all") { record_action("all-zone-policies"); dashboard_.show_detail_header("All configured zone policies", "VERBOSE VIEW"); dashboard_.show_zones(state_, "All zone policies", ZoneView::All, ZoneScope::All); }
            else { logger_.record({LogChannel::Audit, LogLevel::Warning, "invalid-interactive-selection", {}}); dashboard_.show_invalid_selection(); }
        } else if (menu == DashboardMenu::Network) {
            if (choice == "1") { record_action("listeners", LogChannel::Security); dashboard_.show_detail_header("Network-reachable listeners"); dashboard_.show_listeners(state_); }
            else if (choice == "2") { record_action("network-diagnostics"); dashboard_.show_detail_header("Ping and traceroute diagnostics", "EXTERNAL TRAFFIC"); const auto diagnostics = network_diagnostics_.inspect(); bool tool_unavailable = false; for (const auto& probe : diagnostics.probes) tool_unavailable = tool_unavailable || !probe.command_available; for (const auto& trace : diagnostics.traceroutes) tool_unavailable = tool_unavailable || !trace.command_available; if (diagnostics.path_stability) tool_unavailable = tool_unavailable || !diagnostics.path_stability->command_available; for (const auto& resolver : diagnostics.resolver_probes) tool_unavailable = tool_unavailable || !resolver.command_available; if (tool_unavailable) logger_.record({LogChannel::Error, LogLevel::Error, "network-diagnostic-tool-unavailable", {}}); dashboard_.show_network_diagnostics(diagnostics); }
            else if (choice == "3") { record_action("network-metadata"); dashboard_.show_detail_header("Public IP metadata", "EXTERNAL REQUEST"); const auto capture = network_evidence_.capture(false, !state_.vpn.active_tunnel_interfaces.empty()); if (!capture.successful()) logger_.record({LogChannel::Error, LogLevel::Error, "network-metadata-failed", {}}); dashboard_.show_network_metadata(capture.metadata, capture.history_status()); }
            else if (choice == "4") { record_action("network-history"); dashboard_.show_detail_header("Saved network metadata"); const auto history = network_evidence_.read_history(); if (!history.available) logger_.record({LogChannel::Error, LogLevel::Error, "network-history-unavailable", {}}); dashboard_.show_network_history(history.records, history.display_status()); }
            else { logger_.record({LogChannel::Audit, LogLevel::Warning, "invalid-interactive-selection", {}}); dashboard_.show_invalid_selection(); }
        } else {
            if (choice == "1") { record_action("readiness", LogChannel::Security); dashboard_.show_detail_header("DEF CON readiness report"); dashboard_.show_readiness(state_); }
            else if (choice == "2") { record_action("threat-assessment", LogChannel::Security); dashboard_.show_detail_header("Threat evidence assessment"); dashboard_.show_threat_assessment(state_); }
            else if (choice == "3") { record_action("security-advisories", LogChannel::Security); dashboard_.show_detail_header("Security advisories and CVEs", "EXTERNAL PACKAGE METADATA"); const auto report = security_advisories_.inspect(); if (!report.query_succeeded) logger_.record({LogChannel::Error, LogLevel::Error, "security-advisory-query-failed", {}}); dashboard_.show_security_advisories(report); }
            else if (choice == "4") { record_action("log-analysis"); dashboard_.show_detail_header("Local ffc log analysis"); const auto analysis = log_analyzer_.inspect(); if (!analysis.logs_available) logger_.record({LogChannel::Error, LogLevel::Error, "log-analysis-unavailable", {}}); dashboard_.show_log_analysis(analysis); }
            else { logger_.record({LogChannel::Audit, LogLevel::Warning, "invalid-interactive-selection", {}}); dashboard_.show_invalid_selection(); }
        }
        dashboard_.pause(menu);
    } while (true);
    logger_.record({LogChannel::Audit, LogLevel::Info, "interactive-session-end", {}});
    dashboard_.show_goodbye(); return 0;
}
} // namespace ffc
