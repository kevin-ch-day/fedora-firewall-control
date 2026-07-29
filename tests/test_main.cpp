#include "ffc/firewall_state.hpp"
#include "ffc/readiness.hpp"

#include <cstdlib>
#include <iostream>

namespace { int failures = 0; void expect(bool value, const char* text) { if (!value) { std::cerr << "FAILED: " << text << '\n'; ++failures; } } }
int main() {
    const auto zone = ffc::parse_zone_info("interfaces: enp1s0 wlp2s0\nservices: ssh dhcpv6-client\nports: 8080/tcp\nmasquerade: yes\nforward: no\n  rule family=\"ipv4\" service name=\"ssh\" accept\n");
    expect(zone.interfaces.size() == 2, "parses interfaces"); expect(zone.services.size() == 2, "parses services"); expect(zone.ports == std::vector<std::string>{"8080/tcp"}, "parses ports"); expect(zone.masquerade && !zone.forward, "parses booleans"); expect(zone.rich_rules.size() == 1, "counts rich rules");
    const auto active_zones = ffc::parse_active_zones("public (default)\n  interfaces: wlp0s20f3\ntrusted\n  interfaces: enp1s0\n");
    expect(active_zones.size() == 2 && active_zones.at("public") == std::vector<std::string>{"wlp0s20f3"}, "parses active zones");
    ffc::FirewallState state; state.installed = state.active = state.enabled = true; state.default_zone = "public"; state.runtime_zones["public"] = zone; state.permanent_zones["public"] = zone; state.active_zone_interfaces = active_zones;
    const auto checks = ffc::assess_readiness(state); bool found_masquerade = false; for (const auto& check : checks) if (check.label == "masquerading disabled") { found_masquerade = check.level == ffc::CheckLevel::Warn; }
    expect(found_masquerade, "flags masquerading"); return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
