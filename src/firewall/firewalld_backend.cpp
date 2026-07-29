#include "ffc/firewalld_backend.hpp"

#include <algorithm>

namespace ffc {
CommandResult FirewalldCommandBackend::firewalld_cmd(const std::vector<std::string>& args) const {
    std::vector<std::string> command{"firewall-cmd"}; command.insert(command.end(), args.begin(), args.end());
    return runner_.run(command);
}

FirewallState FirewalldCommandBackend::inspect() const {
    FirewallState state;
    const auto version = firewalld_cmd({"--version"});
    state.installed = version.success();
    if (!state.installed) { state.errors.push_back("firewall-cmd unavailable: " + version.stderr_text); return state; }

    const auto running = firewalld_cmd({"--state"}); state.active = running.success() && running.stdout_text.find("running") != std::string::npos;
    const auto enabled = runner_.run({"systemctl", "is-enabled", "firewalld.service"}); state.enabled = enabled.success();
    if (!state.active) { state.errors.push_back("firewalld is not active"); return state; }

    const auto panic = firewalld_cmd({"--query-panic"}); state.panic = panic.success();
    const auto config_check = firewalld_cmd({"--check-config"});
    state.permanent_config_checked = true; state.permanent_config_valid = config_check.success();
    if (!config_check.success()) state.errors.push_back("permanent configuration check failed: " + config_check.stderr_text);
    const auto log_denied = firewalld_cmd({"--get-log-denied"});
    if (log_denied.success()) { const auto values = split_words(log_denied.stdout_text); if (!values.empty()) state.log_denied = values.front(); }
    else state.errors.push_back("could not read denied-packet logging setting: " + log_denied.stderr_text);
    const auto default_zone = firewalld_cmd({"--get-default-zone"});
    if (default_zone.success()) { const auto values = split_words(default_zone.stdout_text); if (!values.empty()) state.default_zone = values.front(); }
    else state.errors.push_back("could not determine default zone: " + default_zone.stderr_text);

    const auto active_zones = firewalld_cmd({"--get-active-zones"});
    if (active_zones.success()) { state.active_zone_interfaces = parse_active_zones(active_zones.stdout_text); state.active_zone_sources = parse_active_zone_sources(active_zones.stdout_text); }
    else state.errors.push_back("could not list active zones: " + active_zones.stderr_text);
    const auto runtime_zones = firewalld_cmd({"--list-all-zones"});
    if (runtime_zones.success()) state.runtime_zones = parse_all_zone_info(runtime_zones.stdout_text);
    else state.errors.push_back("could not inspect runtime zones: " + runtime_zones.stderr_text);
    const auto permanent_zones = firewalld_cmd({"--permanent", "--list-all-zones"});
    if (permanent_zones.success()) state.permanent_zones = parse_all_zone_info(permanent_zones.stdout_text);
    else state.errors.push_back("could not inspect permanent zones: " + permanent_zones.stderr_text);
    const auto policies = firewalld_cmd({"--get-active-policies"});
    if (policies.success()) state.active_policies = parse_active_policy_names(policies.stdout_text);
    else state.errors.push_back("could not list active policies: " + policies.stderr_text);
    return state;
}
} // namespace ffc
