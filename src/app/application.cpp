#include "ffc/application.hpp"

namespace ffc {
int OperationsConsole::run(int argc, char** argv) {
    std::vector<std::string> arguments;
    for (int index = 1; index < argc; ++index) arguments.emplace_back(argv[index]);
    const auto command = parse_command_line(arguments);
    return command.action == CommandAction::Interactive ? interactive_.run() : commands_.execute(command);
}
} // namespace ffc
