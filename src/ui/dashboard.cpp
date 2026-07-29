#include "ffc/dashboard.hpp"

#include <iostream>

namespace ffc {
namespace {
std::string menu_title(DashboardMenu menu) {
    if (menu == DashboardMenu::Readiness)
        return "Readiness and current risk";
    if (menu == DashboardMenu::Monitor)
        return "Current signals and alerts";
    if (menu == DashboardMenu::Firewall)
        return "Firewall and connections";
    if (menu == DashboardMenu::Network)
        return "Network and VPN";
    if (menu == DashboardMenu::Evidence)
        return "Incidents and evidence";
    if (menu == DashboardMenu::Settings)
        return "Settings and component status";
    if (menu == DashboardMenu::Emergency)
        return "Emergency isolation";
    return "Main menu";
}

std::string breadcrumb(const DashboardMenu menu, const std::string& detail = {}) {
    std::string result = "MAIN";
    if (menu != DashboardMenu::Main)
        result += " > " + menu_title(menu);
    if (!detail.empty())
        result += " > " + detail;
    return result;
}
} // namespace
void OperationsDashboard::show_status(const FirewallState &state) const {
    posture_.show_status(state);
}
void OperationsDashboard::show_overview(const FirewallState &state) const {
    posture_.show_overview(state);
}
void OperationsDashboard::show_listeners(const FirewallState &state) const {
    posture_.show_listeners(state);
}
void OperationsDashboard::show_threat_assessment(const FirewallState &state) const {
    posture_.show_threat_assessment(state);
}
void OperationsDashboard::show_network_metadata(const NetworkMetadata &metadata,
                                                const std::string &history_path) const {
    network_.show_metadata(metadata, history_path);
}
void OperationsDashboard::show_network_history(const std::vector<std::string> &records,
                                               const std::string &history_path) const {
    network_.show_history(records, history_path);
}
void OperationsDashboard::show_network_diagnostics(const NetworkDiagnostics &diagnostics) const {
    network_.show_diagnostics(diagnostics);
}
void OperationsDashboard::show_security_advisories(const SecurityAdvisoryReport &report) const {
    advisories_.show(report);
}
void OperationsDashboard::show_log_analysis(const LogAnalysis &analysis) const {
    logs_.show_analysis(analysis);
}
void OperationsDashboard::show_zones(const FirewallState &state, const std::string &title,
                                     ZoneView view, ZoneScope scope) const {
    posture_.show_zones(state, title, view, scope);
}
void OperationsDashboard::show_readiness(const FirewallState &state) const {
    posture_.show_readiness(state);
}
void OperationsDashboard::show_menu(const DashboardState &dashboard, DashboardMenu menu,
                                    const bool expanded_home) const {
    ui_.clear();
    if (menu == DashboardMenu::Main) {
        ui_.heading("DEF CON HOST DEFENSE", "READ-ONLY");
        if (expanded_home)
            posture_.show_dashboard_snapshot(dashboard);
        else
            posture_.show_dashboard_home(dashboard);
        ui_.section("Main menu");
        std::cout << "  " << ui_.keycap("1") << " Readiness/risk"
                  << "  " << ui_.keycap("2") << " Alerts/signals\n"
                  << "  " << ui_.keycap("3") << " Firewall"
                  << "        " << ui_.keycap("4") << " Network/VPN\n"
                  << "  " << ui_.keycap("5") << " Evidence"
                  << "        " << ui_.keycap("6") << " Components\n"
                  << "  " << ui_.keycap("9") << " Emergency isolation " << ui_.warning_badge("NOT INSTALLED") << "\n"
                  << "  " << ui_.keycap("R") << " Refresh"
                  << "  " << ui_.keycap("!") << " Emergency"
                  << "  " << ui_.keycap("H") << " Help"
                  << "  " << ui_.keycap("?") << (expanded_home ? " Compact" : " More")
                  << "  " << ui_.keycap("0/Q") << " Exit\n";
    } else {
        const std::string title = menu_title(menu);
        std::cout << ui_.accent(breadcrumb(menu)) << '\n';
        ui_.rule();
        std::cout << "  " << ui_.muted("Read-only snapshot • B: main • R: refresh • H: help • !: emergency")
                  << '\n';
        ui_.section(title);
        if (menu == DashboardMenu::Readiness) {
            std::cout << "  " << ui_.keycap("1") << " Readiness report and blockers\n"
                      << "  " << ui_.keycap("2") << " Threat evidence assessment\n";
        } else if (menu == DashboardMenu::Monitor) {
            std::cout << "  " << ui_.keycap("1") << " Current threat evidence\n"
                      << "  " << ui_.keycap("2") << " Analyze local ffc logs\n"
                      << "\n  " << ui_.warning("Continuous monitoring is not available in this snapshot build.")
                      << "\n      Refresh reconciles the current local state; it does not watch events in the background.\n";
        } else if (menu == DashboardMenu::Firewall) {
            std::cout << "  " << ui_.keycap("1") << " Firewall service state\n"
                      << "  " << ui_.keycap("2") << " Default and active zones\n"
                      << "  " << ui_.keycap("3") << " Interfaces and zone assignments\n"
                      << "  " << ui_.keycap("4") << " Allowed services\n"
                      << "  " << ui_.keycap("5") << " Explicit open ports\n"
                      << "  " << ui_.keycap("6") << " Rich rules\n"
                      << "  " << ui_.keycap("7") << " Intra-zone forwarding and NAT\n"
                      << "  " << ui_.keycap("8") << " Runtime/permanent differences\n"
                      << "  " << ui_.keycap("A") << " All configured zone policies "
                      << ui_.muted("(verbose)") << '\n';
        } else if (menu == DashboardMenu::Network) {
            std::cout << "  " << ui_.keycap("1") << " Network-reachable listeners\n"
                      << "  " << ui_.keycap("2") << " Ping and traceroute diagnostics "
                      << ui_.muted("(external traffic)") << '\n'
                      << "  " << ui_.keycap("3") << " Query public IP and save metadata "
                      << ui_.muted("(external request)") << '\n'
                      << "  " << ui_.keycap("4") << " View saved network metadata\n";
        } else if (menu == DashboardMenu::Evidence) {
            std::cout << "  " << ui_.keycap("1") << " Threat evidence assessment\n"
                      << "  " << ui_.keycap("2") << " DEF CON readiness report\n"
                      << "  " << ui_.keycap("3") << " Security advisories and CVEs\n"
                      << "  " << ui_.keycap("4") << " Analyze local ffc logs\n";
        } else if (menu == DashboardMenu::Settings) {
            std::cout << "  " << ui_.keycap("1") << " Show assessment and enforcement boundaries\n"
                      << "  " << ui_.keycap("2") << " Show web dashboard availability\n"
                      << "\n  " << ui_.muted("The web dashboard and settings changes are not implemented in this release.")
                      << '\n';
        } else if (menu == DashboardMenu::Emergency) {
            std::cout << "  " << ui_.danger("Emergency controls are intentionally unavailable in this read-only build.")
                      << "\n      No isolation, firewall, NetworkManager, or radio action can run from this screen.\n"
                      << "\n  " << ui_.keycap("1") << " Block new inbound " << ui_.muted("(planned)") << '\n'
                      << "  " << ui_.keycap("2") << " Quarantine host " << ui_.muted("(planned)") << '\n'
                      << "  " << ui_.keycap("3") << " Drop all network traffic " << ui_.muted("(planned)") << '\n'
                      << "  " << ui_.keycap("4") << " Disconnect managed interfaces " << ui_.muted("(planned)") << '\n'
                      << "  " << ui_.keycap("5") << " Full network isolation " << ui_.muted("(planned)") << '\n'
                      << "  " << ui_.keycap("6") << " Restore verified state " << ui_.muted("(planned)") << '\n'
                      << "  " << ui_.keycap("7") << " Show recovery instructions " << ui_.muted("(planned)") << '\n';
        }
        std::cout << "  " << ui_.keycap("B") << " Back to main menu\n"
                  << "  " << ui_.keycap("R") << " Refresh posture snapshot"
                  << "  " << ui_.keycap("H") << " Help"
                  << "  " << ui_.keycap("!") << " Emergency"
                  << "  " << ui_.keycap("0/Q") << " Exit\n";
    }
    ui_.rule();
    std::cout << ui_.accent(menu == DashboardMenu::Main ? "MAIN" : menu_title(menu))
              << ui_.muted(" > ");
}
void OperationsDashboard::show_detail_header(const DashboardMenu menu, const std::string &title,
                                             const std::string &subtitle) const {
    ui_.clear();
    std::cout << ui_.accent(breadcrumb(menu, title)) << '\n';
    ui_.rule();
    std::cout << "  " << ui_.muted("READ-ONLY SNAPSHOT")
              << (subtitle.empty() ? "" : "  •  " + ui_.warning(subtitle)) << '\n';
}
void OperationsDashboard::show_navigation_help(DashboardMenu menu) const {
    ui_.clear();
    std::cout << ui_.accent(breadcrumb(menu, "Help")) << '\n';
    ui_.rule();
    ui_.section("Shared navigation");
    std::cout << "  " << ui_.keycap("B") << " Return to the main menu from a submenu or leave a detail view\n"
              << "  " << ui_.keycap("R") << " Refresh local posture without changing firewall or network settings\n"
              << "  " << ui_.keycap("H") << " Open this help screen\n"
              << "  " << ui_.keycap("?") << " Toggle the compact and expanded home views\n"
              << "  " << ui_.keycap("!") << " Open the emergency-isolation screen; it cannot act in this release\n"
              << "  " << ui_.keycap("0/Q") << " Exit the console\n";
    ui_.section("Operational cues");
    std::cout << "  "
              << ui_.muted("External traffic is marked before it runs; normal "
                           "viewing is local and read-only.")
              << '\n'
              << "  "
              << ui_.muted("Use Incidents and evidence for advisory, triage, and "
                           "application-log review.")
              << '\n';
}
void OperationsDashboard::show_invalid_selection() const {
    std::cout << ui_.danger("Unrecognized command. Use a displayed key or H for help.") << '\n';
}
void OperationsDashboard::show_unavailable_capability(const std::string& capability) const {
    std::cout << ui_.warning(capability +
                             " is not available in this read-only release; no system change was made.")
              << '\n';
}
void OperationsDashboard::show_goodbye() const {
    std::cout << "\n"
              << ui_.success("Firewall Control closed. No firewall changes were made.") << '\n';
}
} // namespace ffc
