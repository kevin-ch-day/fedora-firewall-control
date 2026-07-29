#include "ffc/command_runner.hpp"

#include <algorithm>
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
    for (auto &descriptor : pipe_descriptors) {
        if (descriptor >= 0)
            close(descriptor);
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
    ~ScopedSigpipeIgnore() {
        if (active_)
            sigaction(SIGPIPE, &previous_, nullptr);
    }
    ScopedSigpipeIgnore(const ScopedSigpipeIgnore &) = delete;
    ScopedSigpipeIgnore &operator=(const ScopedSigpipeIgnore &) = delete;

  private:
    struct sigaction previous_{};
    bool active_{false};
};

void append_error(std::string &target, const std::string &detail) {
    if (!target.empty())
        target += '\n';
    target += detail;
}

struct CommunicationResult {
    std::string standard_output;
    std::string standard_error;
    bool timed_out{false};
    bool truncated{false};
    bool output_failed{false};
    bool input_rejected{false};
    bool input_failed{false};
    std::string input_error;
};

CommunicationResult communicate_with_process(const int stdout_descriptor,
                                             const int stderr_descriptor,
                                             const int input_descriptor,
                                             const std::string &standard_input, const pid_t child,
                                             const std::chrono::steady_clock::time_point deadline) {
    CommunicationResult result;
    std::array<pollfd, 3> descriptors{
        {{stdout_descriptor, POLLIN, 0},
         {stderr_descriptor, POLLIN, 0},
         {input_descriptor, static_cast<short>(standard_input.empty() ? 0 : POLLOUT), 0}}};
    int open_descriptors = standard_input.empty() ? 2 : 3;
    std::size_t input_offset = 0;
    bool terminated = false;
    if (standard_input.empty()) {
        close(descriptors[2].fd);
        descriptors[2].fd = -1;
    } else {
        const int flags = fcntl(input_descriptor, F_GETFL);
        if (flags < 0 || fcntl(input_descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
            result.input_failed = true;
            result.input_error = std::strerror(errno);
            kill(child, SIGKILL);
            terminated = true;
            close(descriptors[2].fd);
            descriptors[2].fd = -1;
            --open_descriptors;
        }
    }

    // A consumer may close standard input while output is still being drained.
    // Ignore SIGPIPE here so that becomes a command result instead of ending
    // the console process.
    const ScopedSigpipeIgnore ignore_sigpipe;
    while (open_descriptors > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (!terminated && now >= deadline) {
            kill(child, SIGKILL);
            terminated = result.timed_out = true;
        }
        const int wait_milliseconds =
            terminated
                ? 1000
                : static_cast<int>(std::max<long>(
                      1, std::min<long>(
                             std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
                                 .count(),
                             1000)));
        if (poll(descriptors.data(), descriptors.size(), wait_milliseconds) < 0) {
            if (errno == EINTR)
                continue;
            result.output_failed = true;
            append_error(result.standard_error,
                         std::string("command output polling failed: ") + std::strerror(errno));
            if (!terminated)
                kill(child, SIGKILL);
            for (auto &descriptor : descriptors) {
                if (descriptor.fd >= 0)
                    close(descriptor.fd);
                descriptor.fd = -1;
            }
            break;
        }
        for (std::size_t index = 0; index < descriptors.size(); ++index) {
            auto &descriptor = descriptors[index];
            if (descriptor.fd < 0 || descriptor.revents == 0)
                continue;
            if (descriptor.revents & POLLNVAL) {
                if (index == 2) {
                    result.input_failed = true;
                    result.input_error = "command standard-input descriptor became invalid";
                } else {
                    result.output_failed = true;
                    append_error(result.standard_error, "command output descriptor became invalid");
                }
                if (!terminated) {
                    kill(child, SIGKILL);
                    terminated = true;
                }
                close(descriptor.fd);
                descriptor.fd = -1;
                --open_descriptors;
                continue;
            }
            if (index == 2) {
                if (descriptor.revents & (POLLERR | POLLHUP)) {
                    result.input_rejected = input_offset < standard_input.size();
                    close(descriptor.fd);
                    descriptor.fd = -1;
                    --open_descriptors;
                    continue;
                }
                if (!(descriptor.revents & POLLOUT))
                    continue;
                const ssize_t written = write(descriptor.fd, standard_input.data() + input_offset,
                                              standard_input.size() - input_offset);
                if (written > 0) {
                    input_offset += static_cast<std::size_t>(written);
                    if (input_offset == standard_input.size()) {
                        close(descriptor.fd);
                        descriptor.fd = -1;
                        --open_descriptors;
                    }
                    continue;
                }
                if (written < 0 && errno == EINTR)
                    continue;
                if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    continue;
                if (written < 0 && errno == EPIPE) {
                    result.input_rejected = true;
                } else {
                    result.input_failed = true;
                    result.input_error = std::strerror(errno);
                }
                close(descriptor.fd);
                descriptor.fd = -1;
                --open_descriptors;
                continue;
            }
            if (!(descriptor.revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            std::array<char, 4096> buffer{};
            const ssize_t count = read(descriptor.fd, buffer.data(), buffer.size());
            if (count > 0) {
                auto &target = descriptor.fd == stdout_descriptor ? result.standard_output
                                                                  : result.standard_error;
                const auto remaining = target.size() < maximum_captured_output
                                           ? maximum_captured_output - target.size()
                                           : 0U;
                target.append(buffer.data(), std::min(static_cast<std::size_t>(count), remaining));
                if (static_cast<std::size_t>(count) > remaining && !terminated) {
                    kill(child, SIGKILL);
                    terminated = result.truncated = true;
                }
            }
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0) {
                result.output_failed = true;
                append_error(result.standard_error,
                             std::string("command output read failed: ") + std::strerror(errno));
                if (!terminated) {
                    kill(child, SIGKILL);
                    terminated = true;
                }
            }
            if (count <= 0) {
                close(descriptor.fd);
                descriptor.fd = -1;
                --open_descriptors;
            }
        }
    }
    for (const auto &descriptor : descriptors)
        if (descriptor.fd >= 0)
            close(descriptor.fd);
    return result;
}
} // namespace
CommandResult ProcessCommandRunner::run(const std::vector<std::string> &arguments) const {
    return run_with_input(arguments, {});
}

CommandResult ProcessCommandRunner::run_with_input(const std::vector<std::string> &arguments,
                                                   const std::string &standard_input) const {
    if (arguments.empty())
        return {-1, {}, "empty command"};
    int out_pipe[2]{-1, -1}, err_pipe[2]{-1, -1}, input_pipe[2]{-1, -1};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0 || pipe(input_pipe) != 0) {
        const std::string error = std::strerror(errno);
        close_pipe(out_pipe);
        close_pipe(err_pipe);
        close_pipe(input_pipe);
        return {-1, {}, error};
    }
    const pid_t pid = fork();
    if (pid < 0) {
        const std::string error = std::strerror(errno);
        close_pipe(out_pipe);
        close_pipe(err_pipe);
        close_pipe(input_pipe);
        return {-1, {}, error};
    }
    if (pid == 0) {
        // All call sites use fixed arguments. Pin command discovery and output
        // language so a hostile shell environment cannot redirect a tool or
        // make parser-sensitive output locale dependent.
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("LC_ALL", "C", 1);
        setenv("LANG", "C", 1);
        if (dup2(input_pipe[0], STDIN_FILENO) < 0 || dup2(out_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(err_pipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        close(input_pipe[0]);
        close(input_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        std::vector<char *> argv;
        argv.reserve(arguments.size() + 1);
        for (const auto &argument : arguments)
            argv.push_back(const_cast<char *>(argument.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(input_pipe[0]);
    input_pipe[0] = -1;
    const auto deadline = std::chrono::steady_clock::now() + command_timeout;
    close(out_pipe[1]);
    out_pipe[1] = -1;
    close(err_pipe[1]);
    err_pipe[1] = -1;
    const int stdout_descriptor = out_pipe[0];
    const int stderr_descriptor = err_pipe[0];
    const int input_descriptor = input_pipe[1];
    out_pipe[0] = err_pipe[0] = -1;
    input_pipe[1] = -1;
    auto output_result = communicate_with_process(stdout_descriptor, stderr_descriptor,
                                                  input_descriptor, standard_input, pid, deadline);
    int status{};
    pid_t waited{};
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        append_error(output_result.standard_error,
                     std::string("could not wait for command: ") + std::strerror(errno));
        output_result.output_failed = true;
    }
    if (output_result.timed_out)
        append_error(output_result.standard_error, "command exceeded 60-second safety limit");
    if (output_result.truncated)
        append_error(output_result.standard_error, "command output exceeded 1 MiB safety limit");
    if (output_result.input_rejected)
        append_error(output_result.standard_error, "command did not accept all standard input");
    if (output_result.input_failed)
        append_error(output_result.standard_error,
                     "command standard-input write failed: " + output_result.input_error);
    if (output_result.timed_out || output_result.truncated || output_result.input_rejected ||
        output_result.input_failed || output_result.output_failed)
        return {-1, output_result.standard_output, output_result.standard_error};
    return {WIFEXITED(status) ? WEXITSTATUS(status) : -1, output_result.standard_output,
            output_result.standard_error};
}
} // namespace ffc
