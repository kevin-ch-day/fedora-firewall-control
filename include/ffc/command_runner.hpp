#pragma once

#include <string>
#include <vector>

namespace ffc {
struct CommandResult {
    int exit_code{-1};
    std::string stdout_text;
    std::string stderr_text;
    [[nodiscard]] bool success() const { return exit_code == 0; }
};

class CommandRunner {
public:
    virtual ~CommandRunner() = default;
    virtual CommandResult run(const std::vector<std::string>& arguments) const = 0;
};

class ProcessCommandRunner final : public CommandRunner {
public:
    CommandResult run(const std::vector<std::string>& arguments) const override;
};
} // namespace ffc
