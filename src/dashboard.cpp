#include "ffc/dashboard.hpp"

#include "ffc/readiness.hpp"

#include <iostream>

namespace ffc {
std::string Dashboard::items_or_none(const std::vector<std::string>& items) {
    if (items.empty()) return "none";
    std::string result;
    for (const auto& item : items) result += (result.empty() ? "" : ", ") + item;
    return result;
}

void Dashboard::show_status(const FirewallState& state) const {
    ui_.section("Firewall posture");
    ui_.key_value("Firewalld", state.active ? ui_.success("ACTIVE") : ui_.danger("INACTIVE"));
    ui_.key_value("Boot service", state.enabled ? ui_.success("ENABLED") : ui_.warning("NOT ENABLED"));
    ui_.key_value("Panic mode", state.panic ? ui_.danger("ACTIVE") : ui_.success("OFF"));
    ui_.key_value("Default zone", state.default_zone.empty() ? ui_.warning("unknown") : ui_.accent(state.default_zone));
    for (const auto& error : state.errors) ui_.key_value("Notice", ui_.warning(error));
}

void Dashboard::show_overview(const FirewallState& state) const {
    ui_.section("Active interface assignments");
    bool found = false;
    for (const auto& [zone, interfaces] : state.active_zone_interfaces) for (const auto& interface : interfaces) {
        std::cout << "  " << ui_.accent(interface) << "  " << ui_.muted("→") << "  " << zone
                  << (zone == state.default_zone ? ui_.muted("  default") : "") << '\n';
        found = true;
    }
    if (!found) std::cout << "  " << ui_.muted("No active zone assignments reported.") << '\n';

    size_t services = 0, ports = 0, rich_rules = 0; bool forwarding = false, masquerade = false;
    for (const auto& [zone_name, zone] : state.runtime_zones) {
        if (state.active_zone_interfaces.contains(zone_name)) { services += zone.services.size(); ports += zone.ports.size(); rich_rules += zone.rich_rules.size(); }
        forwarding = forwarding || zone.forward; masquerade = masquerade || zone.masquerade;
    }
    ui_.section("Exposure summary");
    ui_.key_value("Allowed services", services == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(services) + " configured"));
    ui_.key_value("Explicit ports", ports == 0 ? ui_.success("NONE") : ui_.warning(std::to_string(ports) + " configured"));
    ui_.key_value("Rich rules", std::to_string(rich_rules));
    ui_.key_value("Forwarding", forwarding ? ui_.warning("ENABLED") : ui_.success("DISABLED"));
    ui_.key_value("Masquerading", masquerade ? ui_.warning("ENABLED") : ui_.success("DISABLED"));
}

void Dashboard::show_zones(const FirewallState& state, const std::string& title, ZoneView view) const {
    ui_.section(title);
    for (const auto& [name, zone] : state.runtime_zones) {
        std::cout << "  " << ui_.accent(name) << (name == state.default_zone ? ui_.muted("  (default)") : "") << '\n';
        if (view == ZoneView::All || view == ZoneView::Interfaces) ui_.key_value("interfaces", items_or_none(zone.interfaces));
        if (view == ZoneView::All || view == ZoneView::Services) ui_.key_value("services", items_or_none(zone.services));
        if (view == ZoneView::All || view == ZoneView::Ports) ui_.key_value("ports", items_or_none(zone.ports));
        if (view == ZoneView::All || view == ZoneView::RichRules) ui_.key_value("rich rules", std::to_string(zone.rich_rules.size()));
        if (view == ZoneView::All || view == ZoneView::Routing) {
            ui_.key_value("forwarding", zone.forward ? ui_.warning("enabled") : ui_.success("disabled"));
            ui_.key_value("masquerade", zone.masquerade ? ui_.warning("enabled") : ui_.success("disabled"));
        }
        if (view == ZoneView::Drift) {
            const auto permanent = state.permanent_zones.find(name);
            const bool same = permanent != state.permanent_zones.end() && zone_configurations_equal(zone, permanent->second);
            ui_.key_value("configuration", same ? ui_.success("matches permanent") : ui_.warning("differs from permanent"));
        }
        std::cout << '\n';
    }
}

void Dashboard::show_readiness(const FirewallState& state) const {
    ui_.heading("DEF CON Firewall Readiness", "Read-only assessment — review warnings before connecting to hostile networks");
    for (const auto& check : assess_readiness(state)) {
        const std::string result = check.level == CheckLevel::Pass ? ui_.success("PASS") : check.level == CheckLevel::Warn ? ui_.warning("WARN") : check.level == CheckLevel::Fail ? ui_.danger("FAIL") : ui_.muted("INFO");
        std::cout << "  " << result << "  " << check.label << (check.detail.empty() ? "" : ui_.muted(" — " + check.detail)) << '\n';
    }
}

void Dashboard::show_menu(const FirewallState& state) const {
    ui_.clear(); ui_.heading("DEF CON FIREWALL CONTROL", "v0.1.0  •  Read-only posture inspection"); show_status(state); show_overview(state); ui_.section("Choose an action");
    std::cout << "  " << ui_.accent("[1]") << " Firewall service state          " << ui_.accent("[6]") << " Rich-rule count\n"
              << "  " << ui_.accent("[2]") << " Default and active zones        " << ui_.accent("[7]") << " Forwarding and masquerading\n"
              << "  " << ui_.accent("[3]") << " Interfaces and zone assignments " << ui_.accent("[8]") << " Runtime/permanent differences\n"
              << "  " << ui_.accent("[4]") << " Allowed services                " << ui_.accent("[9]") << " DEF CON readiness report\n"
              << "  " << ui_.accent("[5]") << " Explicit open ports             " << ui_.accent("[R]") << " Refresh state\n"
              << "  " << ui_.accent("[0]") << " Exit\n";
    ui_.rule(); std::cout << ui_.accent("Selection") << " > ";
}

void Dashboard::show_detail_header() const { ui_.clear(); ui_.heading("DEF CON FIREWALL CONTROL", "Read-only detail view"); }
void Dashboard::show_invalid_selection() const { std::cout << ui_.danger("Invalid selection.") << '\n'; }
void Dashboard::show_goodbye() const { std::cout << "\n" << ui_.success("Firewall Control closed. No firewall changes were made.") << '\n'; }
void Dashboard::pause() const { std::cout << '\n' << ui_.muted("Press Enter to return to the dashboard..."); std::string ignored; std::getline(std::cin, ignored); }
} // namespace ffc
