#include "ffc/readiness.hpp"

namespace ffc {
std::string to_string(CheckLevel level) {
    switch (level) { case CheckLevel::Pass: return "PASS"; case CheckLevel::Warn: return "WARN"; case CheckLevel::Fail: return "FAIL"; case CheckLevel::Info: return "INFO"; }
    return "INFO";
}

std::vector<ReadinessCheck> assess_readiness(const FirewallState& state) {
    std::vector<ReadinessCheck> checks;
    checks.push_back({"firewalld installed", state.installed ? CheckLevel::Pass : CheckLevel::Fail, {}});
    checks.push_back({"firewalld active", state.active ? CheckLevel::Pass : CheckLevel::Fail, {}});
    checks.push_back({"firewalld enabled at boot", state.enabled ? CheckLevel::Pass : CheckLevel::Warn, {}});
    checks.push_back({"firewalld panic mode", state.panic ? CheckLevel::Fail : CheckLevel::Pass, state.panic ? "panic mode is active" : "off"});
    checks.push_back({"default zone set", state.default_zone.empty() ? CheckLevel::Fail : CheckLevel::Pass, state.default_zone});
    bool forwarding = false, masquerade = false, exposure = false, aligned = true;
    for (const auto& [zone, config] : state.runtime_zones) {
        forwarding = forwarding || config.forward; masquerade = masquerade || config.masquerade;
        if (state.active_zone_interfaces.contains(zone)) exposure = exposure || !config.services.empty() || !config.ports.empty();
        const auto it = state.permanent_zones.find(zone); aligned = aligned && it != state.permanent_zones.end() && zone_configurations_equal(config, it->second);
    }
    checks.push_back({"active interfaces classified", state.active_zone_interfaces.empty() ? CheckLevel::Warn : CheckLevel::Pass,
                      state.active_zone_interfaces.empty() ? "no active zone assignments reported" : "inspect NetworkManager bindings separately"});
    checks.push_back({"inbound services or explicit ports", exposure ? CheckLevel::Warn : CheckLevel::Pass, exposure ? "review configured exposure" : "none"});
    checks.push_back({"forwarding disabled", forwarding ? CheckLevel::Warn : CheckLevel::Pass, {}});
    checks.push_back({"masquerading disabled", masquerade ? CheckLevel::Warn : CheckLevel::Pass, {}});
    checks.push_back({"permanent/runtime state aligned", aligned ? CheckLevel::Pass : CheckLevel::Warn,
                      aligned ? std::string{} : "runtime differs from permanent"});
    return checks;
}
} // namespace ffc
