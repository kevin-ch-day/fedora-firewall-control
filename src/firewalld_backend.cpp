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
    const auto default_zone = firewalld_cmd({"--get-default-zone"});
    if (default_zone.success()) { const auto values = split_words(default_zone.stdout_text); if (!values.empty()) state.default_zone = values.front(); }
    else state.errors.push_back("could not determine default zone: " + default_zone.stderr_text);

    const auto zones = firewalld_cmd({"--get-zones"});
    if (!zones.success()) { state.errors.push_back("could not list zones: " + zones.stderr_text); return state; }
    const auto active_zones = firewalld_cmd({"--get-active-zones"});
    if (active_zones.success()) state.active_zone_interfaces = parse_active_zones(active_zones.stdout_text);
    else state.errors.push_back("could not list active zones: " + active_zones.stderr_text);
    for (const auto& zone : split_words(zones.stdout_text)) {
        const auto runtime = firewalld_cmd({"--zone=" + zone, "--list-all"});
        if (runtime.success()) state.runtime_zones.emplace(zone, parse_zone_info(runtime.stdout_text));
        else state.errors.push_back("could not inspect runtime zone " + zone + ": " + runtime.stderr_text);
        const auto permanent = firewalld_cmd({"--permanent", "--zone=" + zone, "--list-all"});
        if (permanent.success()) state.permanent_zones.emplace(zone, parse_zone_info(permanent.stdout_text));
    }
    return state;
}
} // namespace ffc
