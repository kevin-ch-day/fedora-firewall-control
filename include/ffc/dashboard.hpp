#pragma once

#include "ffc/posture_renderer.hpp"
#include "ffc/network_renderer.hpp"
#include "ffc/log_renderer.hpp"
#include "ffc/terminal_ui.hpp"

#include <string>
namespace ffc {
enum class DashboardMenu { Main, Firewall, Network, Security };

// Operations display façade for menu/chrome plus focused renderer modules.
class OperationsDashboard {
public:
    explicit OperationsDashboard(TerminalUi& ui) : ui_(ui), posture_(ui), network_(ui), logs_(ui) {}
    void show_status(const FirewallState& state) const;
    void show_overview(const FirewallState& state) const;
    void show_listeners(const FirewallState& state) const;
    void show_threat_assessment(const FirewallState& state) const;
    void show_network_metadata(const NetworkMetadata& metadata, const std::string& history_path) const;
    void show_network_history(const std::vector<std::string>& records, const std::string& history_path) const;
    void show_network_diagnostics(const NetworkDiagnostics& diagnostics) const;
    void show_security_advisories(const SecurityAdvisoryReport& report) const;
    void show_log_analysis(const LogAnalysis& analysis) const;
    void show_zones(const FirewallState& state, const std::string& title, ZoneView view, ZoneScope scope = ZoneScope::ActiveAndDefault) const;
    void show_readiness(const FirewallState& state) const;
    void show_menu(const FirewallState& state, DashboardMenu menu) const;
    void show_detail_header(const std::string& title, const std::string& subtitle = {}) const;
    void show_navigation_help(DashboardMenu menu) const;
    void show_invalid_selection() const;
    void show_goodbye() const;
    void pause(DashboardMenu return_menu) const;

private:
    TerminalUi& ui_;
    PostureRenderer posture_;
    NetworkRenderer network_;
    LogRenderer logs_;
};
using Dashboard = OperationsDashboard; // Compatibility name for early integrations.
} // namespace ffc
