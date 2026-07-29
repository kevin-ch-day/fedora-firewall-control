#include "ffc/socket_inspector.hpp"

#include <sstream>

namespace ffc {
namespace {
bool is_loopback_endpoint(const std::string& endpoint) {
    const auto separator = endpoint.rfind(':');
    const auto address = separator == std::string::npos ? endpoint : endpoint.substr(0, separator);
    return address.starts_with("127.") || address.starts_with("[::1]") || address.starts_with("[::ffff:127.");
}
}

std::vector<ListeningSocket> parse_listening_sockets(const std::string& ss_output) {
    std::vector<ListeningSocket> listeners;
    std::istringstream lines(ss_output); std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line); std::vector<std::string> values; std::string value;
        while (fields >> value) values.push_back(value);
        if (values.size() < 6) continue;
        const auto& protocol = values[0];
        if (protocol != "tcp" && protocol != "udp") continue;
        const auto& endpoint = values[4];
        listeners.push_back({protocol, endpoint, is_loopback_endpoint(endpoint)});
    }
    return listeners;
}

SocketState SocketInspector::inspect() const {
    const auto result = runner_.run({"ss", "-H", "-lntu"});
    if (!result.success()) return {false, {}, result.stderr_text.empty() ? "ss listener query failed" : result.stderr_text};
    return {true, parse_listening_sockets(result.stdout_text), {}};
}
} // namespace ffc
