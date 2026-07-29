#include "ffc/dashboard.hpp"

#include <iostream>

namespace ffc {
namespace {
std::string menu_title(DashboardMenu menu) {
    if (menu == DashboardMenu::Firewall) return "Firewall policy";
    if (menu == DashboardMenu::Network) return "Network and exposure";
    if (menu == DashboardMenu::Security) return "Security and local evidence";
    return "Main menu";
}
}
void OperationsDashboard::show_status(const FirewallState& state) const { posture_.show_status(state); }
void OperationsDashboard::show_overview(const FirewallState& state) const { posture_.show_overview(state); }
void OperationsDashboard::show_listeners(const FirewallState& state) const { posture_.show_listeners(state); }
void OperationsDashboard::show_threat_assessment(const FirewallState& state) const { posture_.show_threat_assessment(state); }
void OperationsDashboard::show_network_metadata(const NetworkMetadata& metadata, const std::string& history_path) const { network_.show_metadata(metadata, history_path); }
void OperationsDashboard::show_network_history(const std::vector<std::string>& records, const std::string& history_path) const { network_.show_history(records, history_path); }
void OperationsDashboard::show_network_diagnostics(const NetworkDiagnostics& diagnostics) const { network_.show_diagnostics(diagnostics); }
void OperationsDashboard::show_security_advisories(const SecurityAdvisoryReport& report) const { network_.show_security_advisories(report); }
void OperationsDashboard::show_log_analysis(const LogAnalysis& analysis) const { logs_.show_analysis(analysis); }
void OperationsDashboard::show_zones(const FirewallState& state, const std::string& title, ZoneView view, ZoneScope scope) const { posture_.show_zones(state, title, view, scope); }
void OperationsDashboard::show_readiness(const FirewallState& state) const { posture_.show_readiness(state); }
void OperationsDashboard::show_menu(const FirewallState& state, DashboardMenu menu) const {
    ui_.clear();
    if (menu == DashboardMenu::Main) {
        ui_.heading("DEF CON FIREWALL CONTROL", "READ-ONLY POSTURE CONSOLE  //  THEME: " + ui_.theme_name());
        posture_.show_dashboard_snapshot(state);
        ui_.section("Main menu");
        std::cout << "  " << ui_.keycap("1") << " Firewall policy and posture\n"
                  << "      Zones, services, ports, rules, routing, and configuration drift\n"
                  << "  " << ui_.keycap("2") << " Network and exposure\n"
                  << "      Listeners, optional diagnostics, public-IP history\n"
                  << "  " << ui_.keycap("3") << " Security and local evidence\n"
                  << "      Readiness, advisories, threat evidence, and local logs\n"
                  << "\n  " << ui_.keycap("R") << " Refresh posture snapshot"
                  << "  " << ui_.keycap("H") << " Help"
                  << "  " << ui_.keycap("0/Q") << " Exit\n";
    } else {
        const std::string title = menu_title(menu);
        ui_.heading("DEF CON FIREWALL CONTROL", title + " submenu");
        ui_.section(title + "  " + ui_.muted("(B: main menu • R: refresh • H: help)"));
        if (menu == DashboardMenu::Firewall) {
            std::cout << "  " << ui_.keycap("1") << " Firewall service state\n"
                      << "  " << ui_.keycap("2") << " Default and active zones\n"
                      << "  " << ui_.keycap("3") << " Interfaces and zone assignments\n"
                      << "  " << ui_.keycap("4") << " Allowed services\n"
                      << "  " << ui_.keycap("5") << " Explicit open ports\n"
                      << "  " << ui_.keycap("6") << " Rich rules\n"
                      << "  " << ui_.keycap("7") << " Intra-zone forwarding and NAT\n"
                      << "  " << ui_.keycap("8") << " Runtime/permanent differences\n"
                      << "  " << ui_.keycap("A") << " All configured zone policies " << ui_.muted("(verbose)") << '\n';
        } else if (menu == DashboardMenu::Network) {
            std::cout << "  " << ui_.keycap("1") << " Network-reachable listeners\n"
                      << "  " << ui_.keycap("2") << " Ping and traceroute diagnostics " << ui_.muted("(external traffic)") << '\n'
                      << "  " << ui_.keycap("3") << " Query public IP and save metadata " << ui_.muted("(external request)") << '\n'
                      << "  " << ui_.keycap("4") << " View saved network metadata\n";
        } else {
            std::cout << "  " << ui_.keycap("1") << " DEF CON readiness report\n"
                      << "  " << ui_.keycap("2") << " Threat evidence assessment\n"
                      << "  " << ui_.keycap("3") << " Security advisories and CVEs\n"
                      << "  " << ui_.keycap("4") << " Analyze local ffc logs\n";
        }
        std::cout << "  " << ui_.keycap("B") << " Back to main menu\n"
                  << "  " << ui_.keycap("R") << " Refresh posture snapshot"
                  << "  " << ui_.keycap("H") << " Help"
                  << "  " << ui_.keycap("0/Q") << " Exit\n";
    }
    ui_.rule(); std::cout << ui_.accent(menu == DashboardMenu::Main ? "MAIN" : menu_title(menu)) << ui_.muted(" > ");
}
void OperationsDashboard::show_detail_header(const std::string& title, const std::string& subtitle) const {
    ui_.clear();
    ui_.heading("DEF CON FIREWALL CONTROL", title + "  //  READ-ONLY" + (subtitle.empty() ? "" : "  //  " + subtitle));
}
void OperationsDashboard::show_navigation_help(DashboardMenu menu) const {
    ui_.clear();
    ui_.heading("DEF CON FIREWALL CONTROL", "Navigation help  //  READ-ONLY");
    ui_.section(menu_title(menu));
    std::cout << "  " << ui_.keycap("B") << " Return to the main menu from any submenu\n"
              << "  " << ui_.keycap("R") << " Refresh local firewall posture without changing it\n"
              << "  " << ui_.keycap("H") << " Open this help screen\n"
              << "  " << ui_.keycap("0/Q") << " Exit the console\n";
    ui_.section("Operational cues");
    std::cout << "  " << ui_.muted("External traffic is marked before it runs; normal viewing is local and read-only.") << '\n'
              << "  " << ui_.muted("Use the Security menu for advisory, evidence, and application-log review.") << '\n';
}
void OperationsDashboard::show_invalid_selection() const { std::cout << ui_.danger("Unrecognized command. Use a displayed key or H for help.") << '\n'; }
void OperationsDashboard::show_goodbye() const { std::cout << "\n" << ui_.success("Firewall Control closed. No firewall changes were made.") << '\n'; }
void OperationsDashboard::pause(DashboardMenu return_menu) const { std::cout << '\n' << ui_.muted("Press Enter to return to " + menu_title(return_menu) + "..."); std::string ignored; std::getline(std::cin, ignored); }
} // namespace ffc
