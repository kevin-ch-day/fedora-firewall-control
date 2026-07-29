#include "ffc/command_runner.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ffc {
CommandResult ProcessCommandRunner::run(const std::vector<std::string>& arguments) const {
    if (arguments.empty()) return {-1, {}, "empty command"};
    int out_pipe[2]{}, err_pipe[2]{};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) return {-1, {}, std::strerror(errno)};
    const pid_t pid = fork();
    if (pid < 0) return {-1, {}, std::strerror(errno)};
    if (pid == 0) {
        dup2(out_pipe[1], STDOUT_FILENO); dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
        std::vector<char*> argv; argv.reserve(arguments.size() + 1);
        for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr); execvp(argv[0], argv.data()); _exit(127);
    }
    close(out_pipe[1]); close(err_pipe[1]);
    std::string out, err;
    std::array<pollfd, 2> fds{{{out_pipe[0], POLLIN, 0}, {err_pipe[0], POLLIN, 0}}};
    int open_fds = 2;
    while (open_fds > 0 && poll(fds.data(), fds.size(), -1) >= 0) {
        for (auto& descriptor : fds) {
            if (descriptor.fd < 0 || !(descriptor.revents & (POLLIN | POLLHUP))) continue;
            std::array<char, 4096> buffer{};
            const ssize_t count = read(descriptor.fd, buffer.data(), buffer.size());
            if (count > 0) (descriptor.fd == out_pipe[0] ? out : err).append(buffer.data(), static_cast<size_t>(count));
            if (count <= 0) { close(descriptor.fd); descriptor.fd = -1; --open_fds; }
        }
    }
    for (const auto& descriptor : fds) if (descriptor.fd >= 0) close(descriptor.fd);
    int status{}; waitpid(pid, &status, 0);
    return {WIFEXITED(status) ? WEXITSTATUS(status) : -1, out, err};
}
} // namespace ffc
