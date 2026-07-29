#include "ffc/interactive_session.hpp"
#include "ffc/text_utils.hpp"

#include <iostream>

namespace ffc {
InteractiveSession::InteractiveSession(const PostureInspector &posture,
                                       const NetworkEvidenceService &network_evidence,
                                       const NetworkDiagnosticsInspector &network_diagnostics,
                                       const SecurityAdvisoryInspector &security_advisories,
                                       const LocalLogAnalyzer &log_analyzer, Dashboard &dashboard,
                                       const LoggingEngine &logger)
    : posture_(posture), network_evidence_(network_evidence),
      network_diagnostics_(network_diagnostics), security_advisories_(security_advisories),
      log_analyzer_(log_analyzer), dashboard_(dashboard), logger_(logger) {}

void InteractiveSession::record_action(const std::string_view action,
                                       const LogChannel channel) const {
    logger_.record(
        {channel, LogLevel::Info, "interactive-action", std::string{"action="}.append(action)});
}

void InteractiveSession::refresh(const PostureCollectionDepth depth) {
    logger_.record({LogChannel::Operations, LogLevel::Info, "posture-refresh",
                    depth == PostureCollectionDepth::Landing
                        ? "source=interactive depth=landing"
                        : "source=interactive depth=complete"});
    state_ = posture_.inspect(depth);
}

void InteractiveSession::report_invalid_selection() const {
    logger_.record({LogChannel::Audit, LogLevel::Warning, "invalid-interactive-selection", {}});
    dashboard_.show_invalid_selection();
}

bool InteractiveSession::handle_firewall_selection(const std::string_view choice) {
    if (choice == "1") {
        record_action("status");
        dashboard_.show_detail_header("Firewall service state");
        dashboard_.show_status(state_);
        return true;
    }
    if (choice == "2") {
        record_action("zones");
        dashboard_.show_detail_header("Default and active zones");
        dashboard_.show_zones(state_, "Zones", ZoneView::All);
        return true;
    }
    if (choice == "3") {
        record_action("interfaces");
        dashboard_.show_detail_header("Interfaces and zone assignments");
        dashboard_.show_zones(state_, "Interfaces and zone assignments", ZoneView::Interfaces);
        return true;
    }
    if (choice == "4") {
        record_action("services");
        dashboard_.show_detail_header("Allowed services");
        dashboard_.show_zones(state_, "Allowed services", ZoneView::Services);
        return true;
    }
    if (choice == "5") {
        record_action("ports");
        dashboard_.show_detail_header("Explicit open ports");
        dashboard_.show_zones(state_, "Explicit open ports", ZoneView::Ports);
        return true;
    }
    if (choice == "6") {
        record_action("rich-rules");
        dashboard_.show_detail_header("Rich rules");
        dashboard_.show_zones(state_, "Rich rules", ZoneView::RichRules);
        return true;
    }
    if (choice == "7") {
        record_action("routing");
        dashboard_.show_detail_header("Intra-zone forwarding and NAT");
        dashboard_.show_zones(state_, "Intra-zone forwarding and masquerading", ZoneView::Routing);
        return true;
    }
    if (choice == "8") {
        record_action("configuration-drift", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header("Runtime and permanent differences");
        dashboard_.show_zones(state_, "Runtime/permanent differences", ZoneView::Drift);
        return true;
    }
    if (choice == "a" || choice == "all") {
        record_action("all-zone-policies");
        dashboard_.show_detail_header("All configured zone policies", "VERBOSE VIEW");
        dashboard_.show_zones(state_, "All zone policies", ZoneView::All, ZoneScope::All);
        return true;
    }
    return false;
}

bool InteractiveSession::handle_network_selection(const std::string_view choice) {
    if (choice == "1") {
        record_action("listeners", LogChannel::Security);
        dashboard_.show_detail_header("Network-reachable listeners");
        dashboard_.show_listeners(state_);
        return true;
    }
    if (choice == "2") {
        record_action("network-diagnostics");
        dashboard_.show_detail_header("Ping and traceroute diagnostics", "EXTERNAL TRAFFIC");
        const auto diagnostics = network_diagnostics_.inspect();
        if (diagnostics.has_unavailable_tools()) {
            logger_.record(
                {LogChannel::Error, LogLevel::Error, "network-diagnostic-tool-unavailable", {}});
        }
        dashboard_.show_network_diagnostics(diagnostics);
        return true;
    }
    if (choice == "3") {
        record_action("network-metadata");
        dashboard_.show_detail_header("Public IP metadata", "EXTERNAL REQUEST");
        const auto capture =
            network_evidence_.capture(false, !state_.vpn.active_tunnel_interfaces.empty());
        if (!capture.successful()) {
            logger_.record({LogChannel::Error, LogLevel::Error, "network-metadata-failed", {}});
        }
        dashboard_.show_network_metadata(capture.metadata, capture.history_status());
        return true;
    }
    if (choice == "4") {
        record_action("network-history");
        dashboard_.show_detail_header("Saved network metadata");
        const auto history = network_evidence_.read_history();
        if (!history.available) {
            logger_.record({LogChannel::Error, LogLevel::Error, "network-history-unavailable", {}});
        }
        dashboard_.show_network_history(history.records, history.display_status());
        return true;
    }
    return false;
}

bool InteractiveSession::handle_security_selection(const std::string_view choice) {
    if (choice == "1") {
        record_action("readiness", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header("DEF CON readiness report");
        dashboard_.show_readiness(state_);
        return true;
    }
    if (choice == "2") {
        record_action("threat-assessment", LogChannel::Security);
        refresh(PostureCollectionDepth::Complete);
        dashboard_.show_detail_header("Threat evidence assessment");
        dashboard_.show_threat_assessment(state_);
        return true;
    }
    if (choice == "3") {
        record_action("security-advisories", LogChannel::Security);
        dashboard_.show_detail_header("Security advisories and CVEs", "EXTERNAL PACKAGE METADATA");
        const auto report = security_advisories_.inspect();
        if (!report.query_succeeded) {
            logger_.record(
                {LogChannel::Error, LogLevel::Error, "security-advisory-query-failed", {}});
        }
        dashboard_.show_security_advisories(report);
        return true;
    }
    if (choice == "4") {
        record_action("log-analysis");
        dashboard_.show_detail_header("Local ffc log analysis");
        const auto analysis = log_analyzer_.inspect();
        if (!analysis.logs_available) {
            logger_.record({LogChannel::Error, LogLevel::Error, "log-analysis-unavailable", {}});
        }
        dashboard_.show_log_analysis(analysis);
        return true;
    }
    return false;
}

int InteractiveSession::run() {
    logger_.record({LogChannel::Audit, LogLevel::Info, "interactive-session-start", {}});
    refresh();
    std::string choice;
    DashboardMenu menu = DashboardMenu::Main;
    do {
        dashboard_.show_menu(state_, menu);
        if (!std::getline(std::cin, choice))
            break;
        choice = normalize_command(choice);
        if (choice == "0" || choice == "q" || choice == "quit" || choice == "exit")
            break;
        if (choice == "h" || choice == "help") {
            dashboard_.show_navigation_help(menu);
            dashboard_.pause(menu);
            continue;
        }
        if (choice == "r" || choice == "refresh") {
            record_action("refresh");
            refresh();
            continue;
        }
        if (menu == DashboardMenu::Main) {
            if (choice == "1" || choice == "f" || choice == "firewall") {
                menu = DashboardMenu::Firewall;
                continue;
            }
            if (choice == "2" || choice == "n" || choice == "network") {
                menu = DashboardMenu::Network;
                continue;
            }
            if (choice == "3" || choice == "s" || choice == "security") {
                menu = DashboardMenu::Security;
                continue;
            }
            report_invalid_selection();
            dashboard_.pause(menu);
            continue;
        }
        if (choice == "b" || choice == "back") {
            menu = DashboardMenu::Main;
            continue;
        }

        bool handled = false;
        if (menu == DashboardMenu::Firewall) {
            handled = handle_firewall_selection(choice);
        } else if (menu == DashboardMenu::Network) {
            handled = handle_network_selection(choice);
        } else if (menu == DashboardMenu::Security) {
            handled = handle_security_selection(choice);
        }
        if (!handled)
            report_invalid_selection();
        dashboard_.pause(menu);
    } while (true);
    logger_.record({LogChannel::Audit, LogLevel::Info, "interactive-session-end", {}});
    dashboard_.show_goodbye();
    return 0;
}
} // namespace ffc
