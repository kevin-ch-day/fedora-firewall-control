#include "ffc/command_runner.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ffc {
namespace {
constexpr std::size_t maximum_captured_output = 1024U * 1024U;
constexpr auto command_timeout = std::chrono::seconds(60);
}
CommandResult ProcessCommandRunner::run(const std::vector<std::string>& arguments) const {
    return run_with_input(arguments, {});
}

CommandResult ProcessCommandRunner::run_with_input(const std::vector<std::string>& arguments, const std::string& standard_input) const {
    if (arguments.empty()) return {-1, {}, "empty command"};
    int out_pipe[2]{}, err_pipe[2]{}, input_pipe[2]{};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0 || pipe(input_pipe) != 0) return {-1, {}, std::strerror(errno)};
    const pid_t pid = fork();
    if (pid < 0) return {-1, {}, std::strerror(errno)};
    if (pid == 0) {
        // All call sites use fixed arguments. Pin command discovery and output
        // language so a hostile shell environment cannot redirect a tool or
        // make parser-sensitive output locale dependent.
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("LC_ALL", "C", 1);
        setenv("LANG", "C", 1);
        dup2(input_pipe[0], STDIN_FILENO); dup2(out_pipe[1], STDOUT_FILENO); dup2(err_pipe[1], STDERR_FILENO);
        close(input_pipe[0]); close(input_pipe[1]); close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
        std::vector<char*> argv; argv.reserve(arguments.size() + 1);
        for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr); execvp(argv[0], argv.data()); _exit(127);
    }
    close(input_pipe[0]);
    if (!standard_input.empty()) {
        const char* remaining = standard_input.data(); size_t bytes_remaining = standard_input.size();
        while (bytes_remaining > 0) { const ssize_t written = write(input_pipe[1], remaining, bytes_remaining); if (written <= 0) break; remaining += written; bytes_remaining -= static_cast<size_t>(written); }
    }
    close(input_pipe[1]); close(out_pipe[1]); close(err_pipe[1]);
    std::string out, err;
    std::array<pollfd, 2> fds{{{out_pipe[0], POLLIN, 0}, {err_pipe[0], POLLIN, 0}}};
    int open_fds = 2;
    const auto deadline = std::chrono::steady_clock::now() + command_timeout;
    bool terminated = false, timed_out = false, truncated = false;
    while (open_fds > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (!terminated && now >= deadline) { kill(pid, SIGKILL); terminated = timed_out = true; }
        const int wait_milliseconds = terminated ? 1000 : static_cast<int>(std::min<long>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count(), 1000));
        if (poll(fds.data(), fds.size(), wait_milliseconds) < 0 && errno != EINTR) break;
        for (auto& descriptor : fds) {
            if (descriptor.fd < 0 || !(descriptor.revents & (POLLIN | POLLHUP))) continue;
            std::array<char, 4096> buffer{};
            const ssize_t count = read(descriptor.fd, buffer.data(), buffer.size());
            if (count > 0) {
                auto& target = descriptor.fd == out_pipe[0] ? out : err;
                const auto remaining = target.size() < maximum_captured_output ? maximum_captured_output - target.size() : 0U;
                target.append(buffer.data(), std::min(static_cast<std::size_t>(count), remaining));
                if (static_cast<std::size_t>(count) > remaining && !terminated) { kill(pid, SIGKILL); terminated = truncated = true; }
            }
            if (count <= 0) { close(descriptor.fd); descriptor.fd = -1; --open_fds; }
        }
    }
    for (const auto& descriptor : fds) if (descriptor.fd >= 0) close(descriptor.fd);
    int status{}; waitpid(pid, &status, 0);
    if (timed_out) err += (err.empty() ? "" : "\n") + std::string("command exceeded 60-second safety limit");
    if (truncated) err += (err.empty() ? "" : "\n") + std::string("command output exceeded 1 MiB safety limit");
    if (timed_out || truncated) return {-1, out, err};
    return {WIFEXITED(status) ? WEXITSTATUS(status) : -1, out, err};
}
} // namespace ffc
