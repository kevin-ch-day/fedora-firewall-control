#include "ffc/command_runner.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ffc {
namespace {
constexpr std::size_t maximum_captured_output = 1024U * 1024U;
constexpr auto command_timeout = std::chrono::seconds(60);

void close_pipe(int (&pipe_descriptors)[2]) {
    for (auto& descriptor : pipe_descriptors) {
        if (descriptor >= 0) close(descriptor);
        descriptor = -1;
    }
}

class ScopedSigpipeIgnore {
public:
    ScopedSigpipeIgnore() {
        struct sigaction action{};
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        active_ = sigaction(SIGPIPE, &action, &previous_) == 0;
    }
    ~ScopedSigpipeIgnore() { if (active_) sigaction(SIGPIPE, &previous_, nullptr); }
    ScopedSigpipeIgnore(const ScopedSigpipeIgnore&) = delete;
    ScopedSigpipeIgnore& operator=(const ScopedSigpipeIgnore&) = delete;
private:
    struct sigaction previous_ {};
    bool active_{false};
};
}
CommandResult ProcessCommandRunner::run(const std::vector<std::string>& arguments) const {
    return run_with_input(arguments, {});
}

CommandResult ProcessCommandRunner::run_with_input(const std::vector<std::string>& arguments, const std::string& standard_input) const {
    if (arguments.empty()) return {-1, {}, "empty command"};
    int out_pipe[2]{-1, -1}, err_pipe[2]{-1, -1}, input_pipe[2]{-1, -1};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0 || pipe(input_pipe) != 0) {
        const std::string error = std::strerror(errno);
        close_pipe(out_pipe); close_pipe(err_pipe); close_pipe(input_pipe);
        return {-1, {}, error};
    }
    const pid_t pid = fork();
    if (pid < 0) {
        const std::string error = std::strerror(errno);
        close_pipe(out_pipe); close_pipe(err_pipe); close_pipe(input_pipe);
        return {-1, {}, error};
    }
    if (pid == 0) {
        // All call sites use fixed arguments. Pin command discovery and output
        // language so a hostile shell environment cannot redirect a tool or
        // make parser-sensitive output locale dependent.
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("LC_ALL", "C", 1);
        setenv("LANG", "C", 1);
        if (dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            dup2(out_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(err_pipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        close(input_pipe[0]); close(input_pipe[1]); close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
        std::vector<char*> argv; argv.reserve(arguments.size() + 1);
        for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr); execvp(argv[0], argv.data()); _exit(127);
    }
    close(input_pipe[0]);
    input_pipe[0] = -1;
    const auto deadline = std::chrono::steady_clock::now() + command_timeout;
    bool input_rejected = false, input_write_failed = false, input_timed_out = false;
    std::string input_error;
    if (!standard_input.empty()) {
        // A consumer may reject input or exit before reading it. Treat EPIPE as
        // a command-level failure to accept input, never as a signal that can
        // terminate this defensive console.
        const int flags = fcntl(input_pipe[1], F_GETFL);
        if (flags < 0 || fcntl(input_pipe[1], F_SETFL, flags | O_NONBLOCK) != 0) {
            input_write_failed = true;
            input_error = std::strerror(errno);
        } else {
            const ScopedSigpipeIgnore ignore_sigpipe;
            const char* remaining = standard_input.data(); size_t bytes_remaining = standard_input.size();
            while (bytes_remaining > 0) {
                const ssize_t written = write(input_pipe[1], remaining, bytes_remaining);
                if (written > 0) { remaining += written; bytes_remaining -= static_cast<size_t>(written); continue; }
                if (written < 0 && errno == EINTR) continue;
                if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= deadline) { input_timed_out = true; break; }
                    pollfd input_descriptor{input_pipe[1], POLLOUT, 0};
                    const int wait_milliseconds = static_cast<int>(std::min<long>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count(), 1000));
                    if (poll(&input_descriptor, 1, wait_milliseconds) < 0 && errno != EINTR) { input_write_failed = true; input_error = std::strerror(errno); break; }
                    continue;
                }
                input_rejected = true;
                break;
            }
        }
    }
    close(input_pipe[1]); input_pipe[1] = -1;
    close(out_pipe[1]); out_pipe[1] = -1;
    close(err_pipe[1]); err_pipe[1] = -1;
    std::string out, err;
    const int stdout_descriptor = out_pipe[0];
    std::array<pollfd, 2> fds{{{out_pipe[0], POLLIN, 0}, {err_pipe[0], POLLIN, 0}}};
    int open_fds = 2;
    out_pipe[0] = err_pipe[0] = -1;
    bool terminated = false, timed_out = false, truncated = false, output_failed = false;
    if (input_timed_out || input_write_failed) { kill(pid, SIGKILL); terminated = true; }
    while (open_fds > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (!terminated && now >= deadline) { kill(pid, SIGKILL); terminated = timed_out = true; }
        const int wait_milliseconds = terminated ? 1000 : static_cast<int>(std::min<long>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count(), 1000));
        if (poll(fds.data(), fds.size(), wait_milliseconds) < 0) {
            if (errno == EINTR) continue;
            output_failed = true;
            err += (err.empty() ? "" : "\n") + std::string("command output polling failed: ") + std::strerror(errno);
            if (!terminated) kill(pid, SIGKILL);
            for (auto& descriptor : fds) {
                if (descriptor.fd >= 0) close(descriptor.fd);
                descriptor.fd = -1;
            }
            break;
        }
        for (auto& descriptor : fds) {
            if (descriptor.fd < 0 || descriptor.revents == 0) continue;
            if (descriptor.revents & POLLNVAL) {
                output_failed = true;
                err += (err.empty() ? "" : "\n");
                err += "command output descriptor became invalid";
                if (!terminated) { kill(pid, SIGKILL); terminated = true; }
                close(descriptor.fd); descriptor.fd = -1; --open_fds;
                continue;
            }
            if (!(descriptor.revents & (POLLIN | POLLHUP | POLLERR))) continue;
            std::array<char, 4096> buffer{};
            const ssize_t count = read(descriptor.fd, buffer.data(), buffer.size());
            if (count > 0) {
                auto& target = descriptor.fd == stdout_descriptor ? out : err;
                const auto remaining = target.size() < maximum_captured_output ? maximum_captured_output - target.size() : 0U;
                target.append(buffer.data(), std::min(static_cast<std::size_t>(count), remaining));
                if (static_cast<std::size_t>(count) > remaining && !terminated) { kill(pid, SIGKILL); terminated = truncated = true; }
            }
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) {
                output_failed = true;
                err += (err.empty() ? "" : "\n") + std::string("command output read failed: ") + std::strerror(errno);
                if (!terminated) { kill(pid, SIGKILL); terminated = true; }
            }
            if (count <= 0) { close(descriptor.fd); descriptor.fd = -1; --open_fds; }
        }
    }
    for (const auto& descriptor : fds) if (descriptor.fd >= 0) close(descriptor.fd);
    int status{};
    pid_t waited{};
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0) { err += (err.empty() ? "" : "\n") + std::string("could not wait for command: ") + std::strerror(errno); output_failed = true; }
    if (timed_out) err += (err.empty() ? "" : "\n") + std::string("command exceeded 60-second safety limit");
    if (truncated) err += (err.empty() ? "" : "\n") + std::string("command output exceeded 1 MiB safety limit");
    if (input_timed_out) err += (err.empty() ? "" : "\n") + std::string("command input exceeded 60-second safety limit");
    if (input_rejected) err += (err.empty() ? "" : "\n") + std::string("command did not accept all standard input");
    if (input_write_failed) err += (err.empty() ? "" : "\n") + std::string("command standard-input write failed: ") + input_error;
    if (timed_out || truncated || input_timed_out || input_rejected || input_write_failed || output_failed) return {-1, out, err};
    return {WIFEXITED(status) ? WEXITSTATUS(status) : -1, out, err};
}
} // namespace ffc
