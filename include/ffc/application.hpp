#pragma once

#include "ffc/command_line.hpp"
#include "ffc/command_executor.hpp"
#include "ffc/interactive_session.hpp"

namespace ffc {
// Top-level defensive-operations console that routes a typed command.
class OperationsConsole {
public:
    OperationsConsole(const CommandExecutor& commands, InteractiveSession& interactive) : commands_(commands), interactive_(interactive) {}
    int run(int argc, char** argv);

private:
    const CommandExecutor& commands_;
    InteractiveSession& interactive_;
};
using Application = OperationsConsole; // Compatibility name for early integrations.
} // namespace ffc
