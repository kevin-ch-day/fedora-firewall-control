#pragma once

#include "ffc/command_runner.hpp"

#include <string>
#include <vector>

namespace ffc {
struct ListeningSocket {
    std::string protocol;
    std::string endpoint;
    bool loopback_only{false};
    bool multicast_only{false};
    std::string process_name;
};

struct SocketState {
    bool available{false};
    std::vector<ListeningSocket> listeners;
    bool process_metadata_query_succeeded{false};
    std::string diagnostic;
};

struct ListenerExposureSummary {
    std::size_t non_loopback_bindings{0};
    std::size_t multicast_only_bindings{0};
    std::size_t network_reachable_bindings{0};
    std::size_t logical_network_services{0};
    std::size_t process_attributed_network_bindings{0};
};

std::vector<ListeningSocket> parse_listening_sockets(const std::string& ss_output);
[[nodiscard]] bool is_network_reachable(const ListeningSocket& listener);
[[nodiscard]] ListenerExposureSummary summarize_listener_exposure(const SocketState& state);

// Reads listener endpoints and best-effort process names. PIDs, command lines,
// and packet contents are intentionally not retained.
class SocketInspector {
public:
    explicit SocketInspector(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] SocketState inspect() const;

private:
    const CommandRunner& runner_;
};
} // namespace ffc
