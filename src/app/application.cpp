#include "ffc/application.hpp"

#include <iostream>

namespace ffc {
int OperationsConsole::run(int argc, char** argv) {
    std::vector<std::string> arguments;
    for (int index = 1; index < argc; ++index) arguments.emplace_back(argv[index]);
    const auto command = parse_command_line(arguments);
    const std::string action = command_action_name(command.action);
    const LogChannel action_channel = command.action == CommandAction::Readiness || command.action == CommandAction::Listeners || command.action == CommandAction::ThreatAssessment || command.action == CommandAction::SecurityAdvisories ? LogChannel::Security : LogChannel::Audit;
    bool logging_failure_reported = false;
    const auto record_event = [this, &logging_failure_reported](const LogEvent& event) {
        std::string error;
        if (!logger_.record(event, &error) && !logging_failure_reported) {
            logging_failure_reported = true;
            std::cerr << "Warning: local audit logging is unavailable; continuing without "
                         "persistent audit records.\n";
        }
    };
    record_event({LogChannel::Operations, LogLevel::Info, "application-start", "action=" + action});
    record_event({action_channel, LogLevel::Info, "action-requested", "action=" + action});
    const int result = command.action == CommandAction::Interactive ? interactive_.run() : commands_.execute(command);
    record_event({LogChannel::Operations, result == 0 ? LogLevel::Info : LogLevel::Warning, "application-exit", "action=" + action + " exit_code=" + std::to_string(result)});
    if (result != 0) {
        const std::string detail = "action=" + action + " exit_code=" + std::to_string(result);
        record_event({action_channel, LogLevel::Warning, "action-failed", detail});
        record_event({LogChannel::Error, LogLevel::Error, "action-failed", detail});
    }
    return result;
}
} // namespace ffc
