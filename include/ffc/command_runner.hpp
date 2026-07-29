#pragma once

#include <chrono>
#include <string>
#include <vector>

namespace ffc {
struct CommandResult {
    int exit_code{-1};
    std::string stdout_text;
    std::string stderr_text;
    [[nodiscard]] constexpr bool success() const noexcept { return exit_code == 0; }
};

class CommandRunner {
  public:
    virtual ~CommandRunner() = default;
    virtual CommandResult run(const std::vector<std::string> &arguments) const = 0;
    virtual CommandResult run_with_input(const std::vector<std::string> &arguments,
                                         const std::string &standard_input) const {
        (void)standard_input;
        return run(arguments);
    }
};

class ProcessCommandRunner final : public CommandRunner {
  public:
    explicit ProcessCommandRunner(
        std::chrono::milliseconds timeout = std::chrono::milliseconds{60000},
        std::chrono::milliseconds pipe_drain_grace = std::chrono::milliseconds{2000});
    CommandResult run(const std::vector<std::string> &arguments) const override;
    CommandResult run_with_input(const std::vector<std::string> &arguments,
                                 const std::string &standard_input) const override;

  private:
    std::chrono::milliseconds timeout_;
    std::chrono::milliseconds pipe_drain_grace_;
};
} // namespace ffc
