#include "ffc/dashboard.hpp"

#include <iostream>

namespace ffc {
void OperationsDashboard::show_status(const FirewallState& state) const { posture_.show_status(state); }
void OperationsDashboard::show_overview(const FirewallState& state) const { posture_.show_overview(state); }
void OperationsDashboard::show_listeners(const FirewallState& state) const { posture_.show_listeners(state); }
void OperationsDashboard::show_threat_assessment(const FirewallState& state) const { posture_.show_threat_assessment(state); }
void OperationsDashboard::show_network_metadata(const NetworkMetadata& metadata, const std::string& history_path) const { network_.show_metadata(metadata, history_path); }
void OperationsDashboard::show_network_history(const std::vector<std::string>& records, const std::string& history_path) const { network_.show_history(records, history_path); }
void OperationsDashboard::show_network_diagnostics(const NetworkDiagnostics& diagnostics) const { network_.show_diagnostics(diagnostics); }
void OperationsDashboard::show_security_advisories(const SecurityAdvisoryReport& report) const { network_.show_security_advisories(report); }
void OperationsDashboard::show_zones(const FirewallState& state, const std::string& title, ZoneView view) const { posture_.show_zones(state, title, view); }
void OperationsDashboard::show_readiness(const FirewallState& state) const { posture_.show_readiness(state); }
void OperationsDashboard::show_menu(const FirewallState& state) const { ui_.clear(); ui_.heading("DEF CON FIREWALL CONTROL", "READ-ONLY POSTURE CONSOLE  //  THEME: " + ui_.theme_name()); posture_.show_status(state); posture_.show_overview(state); ui_.section("Command deck"); std::cout << "  " << ui_.keycap("1") << " Firewall service state          " << ui_.keycap("6") << " Rich-rule count\n" << "  " << ui_.keycap("2") << " Default and active zones        " << ui_.keycap("7") << " Intra-zone forwarding and NAT\n" << "  " << ui_.keycap("3") << " Interfaces and zone assignments " << ui_.keycap("8") << " Runtime/permanent differences\n" << "  " << ui_.keycap("4") << " Allowed services                " << ui_.keycap("9") << " DEF CON readiness report\n" << "  " << ui_.keycap("5") << " Explicit open ports             " << ui_.keycap("R") << " Refresh state\n" << "  " << ui_.keycap("L") << " Network-reachable listeners     " << ui_.keycap("T") << " Threat evidence assessment\n" << "  " << ui_.keycap("D") << " Run ping and traceroute diagnostics (external traffic)\n" << "  " << ui_.keycap("S") << " Check available security advisories and CVEs\n" << "  " << ui_.keycap("M") << " Query public IP and save metadata (external request)\n" << "  " << ui_.keycap("H") << " View saved network metadata\n" << "  " << ui_.keycap("0") << " Exit\n"; ui_.rule(); std::cout << ui_.accent("COMMAND") << " > "; }
void OperationsDashboard::show_detail_header() const { ui_.clear(); ui_.heading("DEF CON FIREWALL CONTROL", "Read-only detail view"); }
void OperationsDashboard::show_invalid_selection() const { std::cout << ui_.danger("Invalid selection.") << '\n'; }
void OperationsDashboard::show_goodbye() const { std::cout << "\n" << ui_.success("Firewall Control closed. No firewall changes were made.") << '\n'; }
void OperationsDashboard::pause() const { std::cout << '\n' << ui_.muted("Press Enter to return to the dashboard..."); std::string ignored; std::getline(std::cin, ignored); }
} // namespace ffc
