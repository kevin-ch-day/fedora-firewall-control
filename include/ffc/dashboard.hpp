#pragma once

#include "ffc/firewall_state.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/security_advisories.hpp"
#include "ffc/terminal_ui.hpp"

#include <string>
#include <vector>

namespace ffc {
enum class ZoneView { All, Interfaces, Services, Ports, RichRules, Routing, Drift };

// Presents FirewallState without owning inspection or command-loop behavior.
class Dashboard {
public:
    explicit Dashboard(TerminalUi& ui) : ui_(ui) {}
    void show_status(const FirewallState& state) const;
    void show_overview(const FirewallState& state) const;
    void show_listeners(const FirewallState& state) const;
    void show_network_metadata(const NetworkMetadata& metadata, const std::string& history_path) const;
    void show_network_history(const std::vector<std::string>& records, const std::string& history_path) const;
    void show_network_diagnostics(const NetworkDiagnostics& diagnostics) const;
    void show_security_advisories(const SecurityAdvisoryReport& report) const;
    void show_zones(const FirewallState& state, const std::string& title, ZoneView view) const;
    void show_readiness(const FirewallState& state) const;
    void show_menu(const FirewallState& state) const;
    void show_detail_header() const;
    void show_invalid_selection() const;
    void show_goodbye() const;
    void pause() const;

private:
    TerminalUi& ui_;
    static std::string items_or_none(const std::vector<std::string>& items);
};
} // namespace ffc
