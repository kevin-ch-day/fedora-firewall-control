#pragma once

#include "ffc/dashboard_state.hpp"
#include "ffc/posture_renderer.hpp"
#include "ffc/network_renderer.hpp"
#include "ffc/security_advisory_renderer.hpp"
#include "ffc/log_renderer.hpp"
#include "ffc/terminal_ui.hpp"

#include <string>
namespace ffc {
enum class DashboardMenu { Main, Readiness, Monitor, Firewall, Network, Evidence, Settings, Emergency };

// Operations display façade for menu/chrome plus focused renderer modules.
class OperationsDashboard {
public:
    explicit OperationsDashboard(TerminalUi& ui) : ui_(ui), posture_(ui), network_(ui), advisories_(ui), logs_(ui) {}
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
    void show_menu(const DashboardState& state, DashboardMenu menu, bool expanded_home = false) const;
    void show_detail_header(DashboardMenu menu, const std::string& title,
                            const std::string& subtitle = {}) const;
    void show_navigation_help(DashboardMenu menu) const;
    void show_invalid_selection() const;
    void show_unavailable_capability(const std::string& capability) const;
    void show_goodbye() const;

private:
    TerminalUi& ui_;
    PostureRenderer posture_;
    NetworkRenderer network_;
    SecurityAdvisoryRenderer advisories_;
    LogRenderer logs_;
};
using Dashboard = OperationsDashboard; // Compatibility name for early integrations.
} // namespace ffc
