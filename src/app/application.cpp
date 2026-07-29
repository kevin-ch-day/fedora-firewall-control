#include "ffc/application.hpp"

namespace ffc {
int OperationsConsole::run(int argc, char** argv) {
    std::vector<std::string> arguments;
    for (int index = 1; index < argc; ++index) arguments.emplace_back(argv[index]);
    const auto command = parse_command_line(arguments);
    const std::string action = command_action_name(command.action);
    const LogChannel action_channel = command.action == CommandAction::Readiness || command.action == CommandAction::Listeners || command.action == CommandAction::ThreatAssessment || command.action == CommandAction::SecurityAdvisories ? LogChannel::Security : LogChannel::Audit;
    logger_.record({LogChannel::Operations, LogLevel::Info, "application-start", "action=" + action});
    logger_.record({action_channel, LogLevel::Info, "action-requested", "action=" + action});
    const int result = command.action == CommandAction::Interactive ? interactive_.run() : commands_.execute(command);
    logger_.record({LogChannel::Operations, result == 0 ? LogLevel::Info : LogLevel::Warning, "application-exit", "action=" + action + " exit_code=" + std::to_string(result)});
    if (result != 0) {
        const std::string detail = "action=" + action + " exit_code=" + std::to_string(result);
        logger_.record({action_channel, LogLevel::Warning, "action-failed", detail});
        logger_.record({LogChannel::Error, LogLevel::Error, "action-failed", detail});
    }
    return result;
}
} // namespace ffc
