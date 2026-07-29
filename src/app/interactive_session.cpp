#include "ffc/interactive_session.hpp"
#include "ffc/text_utils.hpp"

#include <iostream>

namespace ffc {
InteractiveSession::InteractiveSession(const PostureInspector& posture,
                                       const NetworkEvidenceService& network_evidence,
                                       const NetworkDiagnosticsInspector& network_diagnostics,
                                       const SecurityAdvisoryInspector& security_advisories,
                                       const LocalLogAnalyzer& log_analyzer, Dashboard& dashboard,
                                       const LoggingEngine& logger)
    : posture_(posture), network_evidence_(network_evidence),
      network_diagnostics_(network_diagnostics), security_advisories_(security_advisories),
      log_analyzer_(log_analyzer), dashboard_(dashboard), logger_(logger) {}

void InteractiveSession::record_action(const std::string_view action,
                                       const LogChannel channel) const {
    record_event(
        {channel, LogLevel::Info, "interactive-action", std::string{"action="}.append(action)});
}

void InteractiveSession::record_event(const LogEvent& event) const {
    std::string error;
    if (!logger_.record(event, &error) && !logging_failure_reported_) {
        logging_failure_reported_ = true;
        std::cerr << "Warning: local audit logging is unavailable; continuing without persistent "
                     "audit records.\n";
    }
}

void InteractiveSession::refresh(const PostureCollectionDepth depth) {
    record_event({LogChannel::Operations, LogLevel::Info, "posture-refresh",
                  depth == PostureCollectionDepth::Landing
                      ? "source=interactive depth=landing"
                      : "source=interactive depth=complete"});
    dashboard_state_ = make_dashboard_snapshot(posture_.inspect(depth), next_snapshot_id_++);
}

void InteractiveSession::report_invalid_selection() const {
    record_event({LogChannel::Audit, LogLevel::Warning, "invalid-interactive-selection", {}});
    dashboard_.show_invalid_selection();
}

bool InteractiveSession::handle_firewall_selection(const std::string_view choice) {
    const auto& state = dashboard_state_.firewall;
    if (choice == "1") {
        record_action("status");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Firewall service state");
        dashboard_.show_status(state);
        return true;
    }
    if (choice == "2") {
        record_action("zones");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Default and active zones");
        dashboard_.show_zones(state, "Zones", ZoneView::All);
        return true;
    }
    if (choice == "3") {
        record_action("interfaces");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Interfaces and zone assignments");
        dashboard_.show_zones(state, "Interfaces and zone assignments", ZoneView::Interfaces);
        return true;
    }
    if (choice == "4") {
        record_action("services");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Allowed services");
        dashboard_.show_zones(state, "Allowed services", ZoneView::Services);
        return true;
    }
    if (choice == "5") {
        record_action("ports");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Explicit open ports");
        dashboard_.show_zones(state, "Explicit open ports", ZoneView::Ports);
        return true;
    }
    if (choice == "6") {
        record_action("rich-rules");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Rich rules");
        dashboard_.show_zones(state, "Rich rules", ZoneView::RichRules);
        return true;
    }
    if (choice == "7") {
        record_action("routing");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Intra-zone forwarding and NAT");
        dashboard_.show_zones(state, "Intra-zone forwarding and masquerading", ZoneView::Routing);
        return true;
    }
    if (choice == "8") {
        record_action("configuration-drift", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header(DashboardMenu::Firewall, "Runtime and permanent differences");
        dashboard_.show_zones(dashboard_state_.firewall, "Runtime/permanent differences", ZoneView::Drift);
        return true;
    }
    if (choice == "a" || choice == "all") {
        record_action("all-zone-policies");
        dashboard_.show_detail_header(DashboardMenu::Firewall, "All configured zone policies", "VERBOSE VIEW");
        dashboard_.show_zones(state, "All zone policies", ZoneView::All, ZoneScope::All);
        return true;
    }
    return false;
}

bool InteractiveSession::handle_network_selection(const std::string_view choice) {
    const auto& state = dashboard_state_.firewall;
    if (choice == "1") {
        record_action("listeners", LogChannel::Security);
        dashboard_.show_detail_header(DashboardMenu::Network, "Network-reachable listeners");
        dashboard_.show_listeners(state);
        return true;
    }
    if (choice == "2") {
        record_action("network-diagnostics");
        dashboard_.show_detail_header(DashboardMenu::Network, "Ping and traceroute diagnostics", "EXTERNAL TRAFFIC");
        const auto diagnostics = network_diagnostics_.inspect();
        if (diagnostics.has_unavailable_tools())
            record_event({LogChannel::Error, LogLevel::Error, "network-diagnostic-tool-unavailable", {}});
        dashboard_.show_network_diagnostics(diagnostics);
        return true;
    }
    if (choice == "3") {
        record_action("network-metadata");
        dashboard_.show_detail_header(DashboardMenu::Network, "Public IP metadata", "EXTERNAL REQUEST");
        const auto capture =
            network_evidence_.capture(false, !state.vpn.active_tunnel_interfaces.empty());
        if (!capture.successful())
            record_event({LogChannel::Error, LogLevel::Error, "network-metadata-failed", {}});
        dashboard_.show_network_metadata(capture.metadata, capture.history_status());
        return true;
    }
    if (choice == "4") {
        record_action("network-history");
        dashboard_.show_detail_header(DashboardMenu::Network, "Saved network metadata");
        const auto history = network_evidence_.read_history();
        if (!history.available)
            record_event({LogChannel::Error, LogLevel::Error, "network-history-unavailable", {}});
        dashboard_.show_network_history(history.records, history.display_status());
        return true;
    }
    return false;
}

bool InteractiveSession::handle_readiness_selection(const std::string_view choice) {
    if (choice == "1") {
        record_action("readiness", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header(DashboardMenu::Readiness, "Readiness report and blockers");
        dashboard_.show_readiness(dashboard_state_.firewall);
        return true;
    }
    if (choice == "2") {
        record_action("threat-assessment", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header(DashboardMenu::Readiness, "Threat evidence assessment");
        dashboard_.show_threat_assessment(dashboard_state_.firewall);
        return true;
    }
    return false;
}

bool InteractiveSession::handle_monitor_selection(const std::string_view choice) {
    if (choice == "1") {
        record_action("monitor-current-evidence", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header(DashboardMenu::Monitor, "Current threat evidence", "POINT-IN-TIME ONLY");
        dashboard_.show_threat_assessment(dashboard_state_.firewall);
        return true;
    }
    if (choice == "2") {
        record_action("monitor-log-analysis");
        dashboard_.show_detail_header(DashboardMenu::Monitor, "Local ffc log analysis");
        const auto analysis = log_analyzer_.inspect();
        if (!analysis.logs_available)
            record_event({LogChannel::Error, LogLevel::Error, "log-analysis-unavailable", {}});
        dashboard_.show_log_analysis(analysis);
        return true;
    }
    return false;
}

bool InteractiveSession::handle_evidence_selection(const std::string_view choice) {
    if (choice == "1") {
        record_action("threat-assessment", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header(DashboardMenu::Evidence, "Threat evidence assessment");
        dashboard_.show_threat_assessment(dashboard_state_.firewall);
        return true;
    }
    if (choice == "2") {
        record_action("readiness", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header(DashboardMenu::Evidence, "DEF CON readiness report");
        dashboard_.show_readiness(dashboard_state_.firewall);
        return true;
    }
    if (choice == "3") {
        record_action("security-advisories", LogChannel::Security);
        dashboard_.show_detail_header(DashboardMenu::Evidence, "Security advisories and CVEs", "EXTERNAL PACKAGE METADATA");
        const auto report = security_advisories_.inspect();
        if (!report.query_succeeded)
            record_event({LogChannel::Error, LogLevel::Error, "security-advisory-query-failed", {}});
        dashboard_.show_security_advisories(report);
        return true;
    }
    if (choice == "4") {
        record_action("log-analysis");
        dashboard_.show_detail_header(DashboardMenu::Evidence, "Local ffc log analysis");
        const auto analysis = log_analyzer_.inspect();
        if (!analysis.logs_available)
            record_event({LogChannel::Error, LogLevel::Error, "log-analysis-unavailable", {}});
        dashboard_.show_log_analysis(analysis);
        return true;
    }
    return false;
}

bool InteractiveSession::handle_settings_selection(const std::string_view choice) {
    if (choice == "1") {
        record_action("assessment-boundaries");
        dashboard_.show_detail_header(DashboardMenu::Settings, "Assessment and enforcement boundaries");
        dashboard_.show_unavailable_capability("Configuration and enforcement controls");
        std::cout << "  Assessment mode affects readiness criteria only. Firewall, NetworkManager, and VPN settings are never changed.\n";
        return true;
    }
    if (choice == "2") {
        record_action("web-dashboard-status");
        dashboard_.show_detail_header(DashboardMenu::Settings, "Web dashboard availability");
        dashboard_.show_unavailable_capability("The loopback web dashboard");
        std::cout << "  A future dashboard will consume cached read-only state; this console does not listen on a network port.\n";
        return true;
    }
    return false;
}

bool InteractiveSession::handle_emergency_selection(const std::string_view choice) {
    if (choice.size() == 1U && choice.front() >= '1' && choice.front() <= '7') {
        record_action("emergency-control-request", LogChannel::Security);
        dashboard_.show_unavailable_capability("Emergency isolation controls");
        return true;
    }
    return false;
}

int InteractiveSession::run() {
    record_event({LogChannel::Audit, LogLevel::Info, "interactive-session-start", {}});
    refresh();
    std::string choice;
    DashboardMenu menu = DashboardMenu::Main;
    bool detail_open = false;
    bool expanded_home = false;
    do {
        if (!detail_open)
            dashboard_.show_menu(dashboard_state_, menu, expanded_home);
        else
            std::cout << "\n" << "  [B] Back  [R] Refresh menu  [H] Help  [!] Emergency  [0/Q] Exit\n"
                      << "VIEW > ";
        if (!std::getline(std::cin, choice))
            break;
        choice = normalize_command(choice);
        if (choice == "0" || choice == "q" || choice == "quit" || choice == "exit")
            break;
        if (choice == "!") {
            menu = DashboardMenu::Emergency;
            detail_open = false;
            continue;
        }
        if (choice == "h" || choice == "help") {
            dashboard_.show_navigation_help(menu);
            detail_open = true;
            continue;
        }
        if (choice == "r" || choice == "refresh") {
            record_action("refresh");
            refresh();
            detail_open = false;
            continue;
        }
        if (!detail_open && menu == DashboardMenu::Main && (choice == "?" || choice == "more")) {
            expanded_home = !expanded_home;
            continue;
        }
        if (detail_open) {
            if (choice == "b" || choice == "back") {
                detail_open = false;
                continue;
            }
            report_invalid_selection();
            continue;
        }
        if (menu == DashboardMenu::Main) {
            if (choice == "1" || choice == "readiness") menu = DashboardMenu::Readiness;
            else if (choice == "2" || choice == "monitor") menu = DashboardMenu::Monitor;
            else if (choice == "3" || choice == "firewall") menu = DashboardMenu::Firewall;
            else if (choice == "4" || choice == "network") menu = DashboardMenu::Network;
            else if (choice == "5" || choice == "evidence") menu = DashboardMenu::Evidence;
            else if (choice == "6" || choice == "settings") menu = DashboardMenu::Settings;
            else if (choice == "9" || choice == "emergency") menu = DashboardMenu::Emergency;
            else report_invalid_selection();
            continue;
        }
        if (choice == "b" || choice == "back") {
            menu = DashboardMenu::Main;
            continue;
        }

        bool handled = false;
        if (menu == DashboardMenu::Readiness) handled = handle_readiness_selection(choice);
        else if (menu == DashboardMenu::Monitor) handled = handle_monitor_selection(choice);
        else if (menu == DashboardMenu::Firewall) handled = handle_firewall_selection(choice);
        else if (menu == DashboardMenu::Network) handled = handle_network_selection(choice);
        else if (menu == DashboardMenu::Evidence) handled = handle_evidence_selection(choice);
        else if (menu == DashboardMenu::Settings) handled = handle_settings_selection(choice);
        else if (menu == DashboardMenu::Emergency) handled = handle_emergency_selection(choice);
        if (!handled)
            report_invalid_selection();
        detail_open = handled;
    } while (true);
    record_event({LogChannel::Audit, LogLevel::Info, "interactive-session-end", {}});
    dashboard_.show_goodbye();
    return 0;
}
} // namespace ffc
