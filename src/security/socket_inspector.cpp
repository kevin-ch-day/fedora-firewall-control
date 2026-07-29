#include "ffc/socket_inspector.hpp"

#include <cctype>
#include <charconv>
#include <set>
#include <sstream>

namespace ffc {
namespace {
bool is_loopback_endpoint(const std::string &endpoint) {
    const auto separator = endpoint.rfind(':');
    const auto address = separator == std::string::npos ? endpoint : endpoint.substr(0, separator);
    return address.starts_with("127.") || address.starts_with("[::1]") ||
           address.starts_with("[::ffff:127.");
}

bool is_multicast_endpoint(const std::string &endpoint) {
    const auto separator = endpoint.rfind(':');
    if (separator == std::string::npos)
        return false;
    auto address = endpoint.substr(0, separator);
    if (address.starts_with('[')) {
        const auto closing = address.find(']');
        if (closing == std::string::npos)
            return false;
        address = address.substr(1, closing - 1);
        return address.size() >= 2 && std::tolower(static_cast<unsigned char>(address[0])) == 'f' &&
               std::tolower(static_cast<unsigned char>(address[1])) == 'f';
    }
    const auto dot = address.find('.');
    const auto first_octet = address.substr(0, dot);
    unsigned int parsed{};
    const auto [position, error] =
        std::from_chars(first_octet.data(), first_octet.data() + first_octet.size(), parsed);
    return error == std::errc{} && position == first_octet.data() + first_octet.size() &&
           parsed >= 224U && parsed <= 239U;
}

std::string endpoint_port(const std::string &endpoint) {
    const auto separator = endpoint.rfind(':');
    return separator == std::string::npos ? std::string{} : endpoint.substr(separator + 1);
}

std::string process_name(const std::string &line) {
    constexpr std::string_view marker{"users:((\""};
    const auto start = line.find(marker);
    if (start == std::string::npos)
        return {};
    const auto name_start = start + marker.size();
    const auto name_end = line.find('"', name_start);
    return name_end == std::string::npos ? std::string{}
                                         : line.substr(name_start, name_end - name_start);
}
} // namespace

std::vector<ListeningSocket> parse_listening_sockets(const std::string &ss_output) {
    std::vector<ListeningSocket> listeners;
    std::istringstream lines(ss_output);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::vector<std::string> values;
        std::string value;
        while (fields >> value)
            values.push_back(value);
        if (values.size() < 6)
            continue;
        const auto &protocol = values[0];
        if (protocol != "tcp" && protocol != "udp")
            continue;
        const auto &endpoint = values[4];
        listeners.push_back({protocol, endpoint, is_loopback_endpoint(endpoint),
                             is_multicast_endpoint(endpoint), process_name(line)});
    }
    return listeners;
}

bool is_network_reachable(const ListeningSocket &listener) {
    return !listener.loopback_only && !listener.multicast_only;
}

ListenerExposureSummary summarize_listener_exposure(const SocketState &state) {
    ListenerExposureSummary summary;
    std::set<std::string> services;
    for (const auto &listener : state.listeners) {
        if (listener.loopback_only)
            continue;
        ++summary.non_loopback_bindings;
        if (listener.multicast_only) {
            ++summary.multicast_only_bindings;
            continue;
        }
        ++summary.network_reachable_bindings;
        if (!listener.process_name.empty())
            ++summary.process_attributed_network_bindings;
        const auto port = endpoint_port(listener.endpoint);
        if (!port.empty())
            services.insert(listener.protocol + "/" + port);
    }
    summary.logical_network_services = services.size();
    return summary;
}

SocketState SocketInspector::inspect() const {
    const auto result = runner_.run({"ss", "-H", "-lntup"});
    SocketState state;
    if (!result.success()) {
        state.diagnostic =
            result.stderr_text.empty() ? "ss listener query failed" : result.stderr_text;
        return state;
    }
    state.available = true;
    // `ss -p` was requested, but unprivileged output can still omit process
    // names for sockets owned by other users.
    state.process_metadata_requested = true;
    state.listeners = parse_listening_sockets(result.stdout_text);
    return state;
}
} // namespace ffc
