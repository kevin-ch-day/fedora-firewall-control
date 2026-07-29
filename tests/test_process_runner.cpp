#include "test_support.hpp"

#include "ffc/terminal_ui.hpp"

#include <string>

namespace ffc::test {
void run_process_runner_tests() {
    const ProcessCommandRunner runner;
    const auto empty = runner.run({});
    const auto stderr_result = runner.run({"/bin/sh", "-c", "printf stdout; printf stderr >&2; exit 7"});
    const auto missing = runner.run({"ffc-command-that-does-not-exist"});
    const auto signaled = runner.run({"/bin/sh", "-c", "kill -TERM $$"});
    const auto closed_input = runner.run_with_input({"/bin/sh", "-c", "exec 0<&-; sleep 0.05"}, std::string(128U * 1024U, 'x'));
    const auto unread_input = runner.run_with_input({"/bin/sh", "-c", "sleep 0.05"}, std::string(128U * 1024U, 'x'));
    const auto excessive_output = runner.run({"/bin/sh", "-c", "head -c 1048577 /dev/zero"});
    expect(empty.exit_code == -1 && !empty.stderr_text.empty(), "rejects empty process commands safely");
    expect(stderr_result.exit_code == 7 && stderr_result.stdout_text == "stdout" && stderr_result.stderr_text == "stderr", "captures independent stdout stderr and exit status");
    expect(missing.exit_code == 127 && signaled.exit_code == -1, "reports unavailable and signaled commands without a shell");
    expect(closed_input.exit_code == -1 && closed_input.stderr_text.find("did not accept all standard input") != std::string::npos, "survives a child closing standard input");
    expect(unread_input.exit_code == -1 && unread_input.stderr_text.find("did not accept all standard input") != std::string::npos, "bounds a child that keeps input open without reading");
    expect(excessive_output.exit_code == -1 && excessive_output.stdout_text.size() == 1024U * 1024U && excessive_output.stderr_text.find("output exceeded 1 MiB safety limit") != std::string::npos, "bounds excessively noisy child output");
    const TerminalUi plain_ui;
    expect(plain_ui.success_badge("READY") == "[ READY ]" && plain_ui.keycap("R") == "[ R ]", "keeps terminal badges legible without color");
}
} // namespace ffc::test
