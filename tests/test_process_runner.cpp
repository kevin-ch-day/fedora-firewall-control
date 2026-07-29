#include "test_support.hpp"

#include "ffc/terminal_ui.hpp"

#include <chrono>
#include <string>

namespace ffc::test {
void run_process_runner_tests() {
    const ProcessCommandRunner runner;
    const ProcessCommandRunner short_timeout_runner(std::chrono::milliseconds{50},
                                                    std::chrono::milliseconds{50});
    const auto empty = runner.run({});
    const auto stderr_result =
        runner.run({"/bin/sh", "-c", "printf stdout; printf stderr >&2; exit 7"});
    const auto missing = runner.run({"ffc-command-that-does-not-exist"});
    const auto signaled = runner.run({"/bin/sh", "-c", "kill -TERM $$"});
    const auto closed_input = runner.run_with_input({"/bin/sh", "-c", "exec 0<&-; sleep 0.05"},
                                                    std::string(128U * 1024U, 'x'));
    const auto unread_input =
        runner.run_with_input({"/bin/sh", "-c", "sleep 0.05"}, std::string(128U * 1024U, 'x'));
    const auto excessive_output = runner.run({"/bin/sh", "-c", "head -c 1048577 /dev/zero"});
    const auto output_before_input =
        runner.run_with_input({"/bin/sh", "-c", "head -c 131072 /dev/zero; cat >/dev/null"},
                              std::string(128U * 1024U, 'x'));
    const auto descendant_start = std::chrono::steady_clock::now();
    const auto descendant_output =
        runner.run({"/bin/sh", "-c", "(sleep 3) & head -c 1048577 /dev/zero"});
    const auto descendant_elapsed = std::chrono::steady_clock::now() - descendant_start;
    const auto timeout = short_timeout_runner.run({"/bin/sh", "-c", "sleep 1"});
    const auto recovery = runner.run({"/bin/true"});
    expect(empty.exit_code == -1 && !empty.stderr_text.empty(),
           "rejects empty process commands safely");
    expect(stderr_result.exit_code == 7 && stderr_result.stdout_text == "stdout" &&
               stderr_result.stderr_text == "stderr",
           "captures independent stdout stderr and exit status");
    expect(missing.exit_code == 127 &&
               missing.stderr_text.find("could not execute command") != std::string::npos &&
               missing.stderr_text.find("ffc-command-that-does-not-exist") != std::string::npos &&
               missing.stderr_text.find("No such file or directory") != std::string::npos &&
               signaled.exit_code == -1,
           "reports unavailable and signaled commands without a shell");
    expect(closed_input.exit_code == -1 &&
               closed_input.stderr_text.find("did not accept all standard input") !=
                   std::string::npos,
           "survives a child closing standard input");
    expect(unread_input.exit_code == -1 &&
               unread_input.stderr_text.find("did not accept all standard input") !=
                   std::string::npos,
           "bounds a child that keeps input open without reading");
    expect(excessive_output.exit_code == -1 &&
               excessive_output.stdout_text.size() == 1024U * 1024U &&
               excessive_output.stderr_text.find("output exceeded 1 MiB safety limit") !=
                   std::string::npos,
           "bounds excessively noisy child output");
    expect(output_before_input.exit_code == 0 &&
               output_before_input.stdout_text.size() == 128U * 1024U,
           "drains output while feeding input so pipe ordering cannot deadlock a command");
    expect(descendant_output.exit_code == -1 && descendant_elapsed < std::chrono::seconds(2),
           "terminates descendant-held output pipes without an unbounded drain wait");
    expect(timeout.exit_code == -1 &&
               timeout.stderr_text.find("50-millisecond safety limit") != std::string::npos,
           "reports ordinary command timeout separately from output-limit termination");
    expect(recovery.exit_code == 0,
           "runs a normal command successfully after process failures and termination");
    const TerminalUi plain_ui;
    expect(plain_ui.success_badge("READY") == "[ READY ]" && plain_ui.keycap("R") == "[ R ]",
           "keeps terminal badges legible without color");
}
} // namespace ffc::test
