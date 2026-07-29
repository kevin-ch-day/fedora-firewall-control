#pragma once

#include "ffc/command_line.hpp"
#include "ffc/command_executor.hpp"
#include "ffc/interactive_session.hpp"
#include "ffc/logging_engine.hpp"

namespace ffc {
// Top-level defensive-operations console that routes a typed command.
class OperationsConsole {
public:
    OperationsConsole(const CommandExecutor& commands, InteractiveSession& interactive, const LoggingEngine& logger) : commands_(commands), interactive_(interactive), logger_(logger) {}
    int run(int argc, char** argv);

private:
    const CommandExecutor& commands_;
    InteractiveSession& interactive_;
    const LoggingEngine& logger_;
};
using Application = OperationsConsole; // Compatibility name for early integrations.
} // namespace ffc
