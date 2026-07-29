#pragma once

#include "ffc/firewall_state.hpp"
#include "ffc/terminal_ui.hpp"

#include <string>
#include <vector>

namespace ffc {
enum class ZoneView { All, Interfaces, Services, Ports, RichRules, Routing, Drift };
enum class ZoneScope { ActiveAndDefault, All };

class PostureRenderer {
public:
    explicit PostureRenderer(TerminalUi& ui) : ui_(ui) {}
    void show_status(const FirewallState& state) const;
    void show_dashboard_snapshot(const FirewallState& state) const;
    void show_overview(const FirewallState& state) const;
    void show_listeners(const FirewallState& state) const;
    void show_threat_assessment(const FirewallState& state) const;
    void show_zones(const FirewallState& state, const std::string& title, ZoneView view, ZoneScope scope = ZoneScope::ActiveAndDefault) const;
    void show_readiness(const FirewallState& state) const;

private:
    TerminalUi& ui_;
    static std::string items_or_none(const std::vector<std::string>& items);
};
} // namespace ffc
