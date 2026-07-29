#pragma once

#include "ffc/command_runner.hpp"

#include <string>
#include <vector>

namespace ffc {
struct ListeningSocket {
    std::string protocol;
    std::string endpoint;
    bool loopback_only{false};
};

struct SocketState {
    bool available{false};
    std::vector<ListeningSocket> listeners;
    std::string diagnostic;
};

std::vector<ListeningSocket> parse_listening_sockets(const std::string& ss_output);

// Reads socket metadata without process names, PIDs, or packet capture.
class SocketInspector {
public:
    explicit SocketInspector(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] SocketState inspect() const;

private:
    const CommandRunner& runner_;
};
} // namespace ffc
