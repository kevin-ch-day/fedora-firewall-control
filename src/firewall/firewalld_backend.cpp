#include "ffc/firewalld_backend.hpp"
#include "ffc/text_utils.hpp"

#include <algorithm>
#include <array>

namespace ffc {
namespace {
bool command_responded(const CommandResult &result) { return result.exit_code >= 0; }

ObservationStatus parse_service_enablement(const CommandResult &result, bool &enabled) {
    enabled = false;
    if (!command_responded(result))
        return ObservationStatus::Unavailable;
    const auto values = split_words(result.stdout_text);
    if (values.empty())
        return ObservationStatus::Partial;
    constexpr std::array<std::string_view, 10> known_states{
        "enabled",  "enabled-runtime", "disabled",  "masked", "static",
        "indirect", "generated",       "transient", "linked", "linked-runtime"};
    if (std::find(known_states.begin(), known_states.end(), values.front()) == known_states.end())
        return ObservationStatus::Partial;
    enabled = values.front() == "enabled" || values.front() == "enabled-runtime";
    return ObservationStatus::Available;
}

bool known_log_denied_value(const std::string_view value) {
    constexpr std::array<std::string_view, 5> values{"off", "all", "unicast", "broadcast",
                                                       "multicast"};
    return std::find(values.begin(), values.end(), value) != values.end();
}

bool has_recognized_zone_details(const std::map<std::string, ZoneState>& zones) {
    return std::any_of(zones.begin(), zones.end(), [](const auto& entry) {
        return entry.second.details_valid && !entry.second.target.empty();
    });
}
} // namespace

CommandResult FirewalldCommandBackend::firewalld_cmd(const std::vector<std::string> &args) const {
    std::vector<std::string> command{"firewall-cmd"};
    command.insert(command.end(), args.begin(), args.end());
    return runner_.run(command);
}

FirewallState FirewalldCommandBackend::inspect(const PostureCollectionDepth depth) const {
    FirewallState state;
    const auto version = firewalld_cmd({"--version"});
    state.installed = version.success();
    state.installation_status =
        state.installed ? ObservationStatus::Available : ObservationStatus::Unavailable;
    if (!state.installed) {
        state.errors.push_back("firewall-cmd unavailable: " + version.stderr_text);
        return state;
    }

    const auto running = firewalld_cmd({"--state"});
    const auto running_values = split_words(running.stdout_text);
    state.active =
        running.success() && running_values.size() == 1U && running_values.front() == "running";
    const bool explicitly_inactive =
        running_values.size() == 2U && running_values[0] == "not" && running_values[1] == "running";
    state.service_state = (state.active || explicitly_inactive) ? ObservationStatus::Available
                                                                : ObservationStatus::Unavailable;
    const auto enabled = runner_.run({"systemctl", "is-enabled", "firewalld.service"});
    state.service_enablement = parse_service_enablement(enabled, state.enabled);
    if (!state.active) {
        state.errors.push_back(observation_available(state.service_state)
                                   ? "firewalld is not active"
                                   : "could not determine whether firewalld is active: " +
                                         running.stderr_text);
        return state;
    }

    const auto panic = firewalld_cmd({"--query-panic"});
    state.panic_state = (panic.exit_code == 0 || panic.exit_code == 1)
                            ? ObservationStatus::Available
                            : ObservationStatus::Unavailable;
    state.panic = panic.exit_code == 0;
    if (!observation_available(state.panic_state))
        state.errors.push_back("could not query panic mode: " + panic.stderr_text);
    const auto config_check = firewalld_cmd({"--check-config"});
    state.permanent_config_checked = command_responded(config_check);
    state.permanent_config = state.permanent_config_checked ? ObservationStatus::Available
                                                            : ObservationStatus::Unavailable;
    state.permanent_config_valid = config_check.success();
    if (!config_check.success())
        state.errors.push_back("permanent configuration check failed: " + config_check.stderr_text);
    const auto log_denied = firewalld_cmd({"--get-log-denied"});
    if (log_denied.success()) {
        const auto values = split_words(log_denied.stdout_text);
        if (values.size() == 1U && known_log_denied_value(values.front())) {
            state.log_denied = values.front();
            state.denied_logging_status = ObservationStatus::Available;
        } else {
            state.denied_logging_status = ObservationStatus::Partial;
            state.errors.push_back("denied-packet logging query returned no value");
        }
    } else
        state.errors.push_back("could not read denied-packet logging setting: " +
                               log_denied.stderr_text);
    const auto default_zone = firewalld_cmd({"--get-default-zone"});
    if (default_zone.success()) {
        const auto values = split_words(default_zone.stdout_text);
        if (values.size() == 1U) {
            state.default_zone = values.front();
            state.default_zone_status = ObservationStatus::Available;
        } else {
            state.default_zone_status = ObservationStatus::Partial;
            state.errors.push_back("default-zone query returned no value");
        }
    } else
        state.errors.push_back("could not determine default zone: " + default_zone.stderr_text);

    const auto active_zones = firewalld_cmd({"--get-active-zones"});
    if (active_zones.success()) {
        state.active_zone_interfaces = parse_active_zones(active_zones.stdout_text);
        state.active_zone_sources = parse_active_zone_sources(active_zones.stdout_text);
        state.active_zones_status = trim_copy(active_zones.stdout_text).empty() ||
                                            !state.active_zone_interfaces.empty() ||
                                            !state.active_zone_sources.empty()
                                        ? ObservationStatus::Available
                                        : ObservationStatus::Partial;
        if (!observation_available(state.active_zones_status))
            state.errors.push_back("active-zone query returned unrecognized output");
    } else
        state.errors.push_back("could not list active zones: " + active_zones.stderr_text);
    const auto runtime_zones = firewalld_cmd({"--list-all-zones"});
    if (runtime_zones.success()) {
        state.runtime_zones = parse_all_zone_info(runtime_zones.stdout_text);
        state.runtime_zones_status = has_recognized_zone_details(state.runtime_zones)
                                         ? ObservationStatus::Available
                                         : ObservationStatus::Partial;
        if (!observation_available(state.runtime_zones_status))
            state.errors.push_back("runtime-zone query returned no recognized zones");
    } else
        state.errors.push_back("could not inspect runtime zones: " + runtime_zones.stderr_text);
    if (depth == PostureCollectionDepth::Complete) {
        const auto permanent_zones = firewalld_cmd({"--permanent", "--list-all-zones"});
        if (permanent_zones.success()) {
            state.permanent_zones = parse_all_zone_info(permanent_zones.stdout_text);
            state.permanent_zones_status = has_recognized_zone_details(state.permanent_zones)
                                               ? ObservationStatus::Available
                                               : ObservationStatus::Partial;
            if (!observation_available(state.permanent_zones_status))
                state.errors.push_back("permanent-zone query returned no recognized zones");
        } else
            state.errors.push_back("could not inspect permanent zones: " +
                                   permanent_zones.stderr_text);
        const auto policies = firewalld_cmd({"--get-active-policies"});
        if (policies.success()) {
            state.active_policies = parse_active_policy_names(policies.stdout_text);
            state.active_policies_status = trim_copy(policies.stdout_text).empty() ||
                                                !state.active_policies.empty()
                                            ? ObservationStatus::Available
                                            : ObservationStatus::Partial;
            if (!observation_available(state.active_policies_status))
                state.errors.push_back("active-policy query returned unrecognized output");
        } else
            state.errors.push_back("could not list active policies: " + policies.stderr_text);
    }
    if (observation_available(state.default_zone_status) &&
        observation_available(state.runtime_zones_status) &&
        !state.runtime_zones.contains(state.default_zone)) {
        state.default_zone_status = ObservationStatus::Partial;
        state.errors.push_back("default zone is absent from runtime-zone output");
    }
    return state;
}
} // namespace ffc
