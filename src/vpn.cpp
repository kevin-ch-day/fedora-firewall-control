#include "ffc/vpn.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace ffc {
namespace {
bool looks_like_tunnel(const std::string& name) {
    const auto lower = [&name] { std::string result = name; std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); }); return result; }();
    return lower == "nordlynx" || lower.starts_with("wg") || lower.starts_with("tun") || lower.starts_with("tap") || lower.starts_with("tailscale") || lower.starts_with("zt");
}
}

std::vector<std::string> parse_vpn_tunnel_interfaces(const std::string& ip_link_output) {
    std::vector<std::string> tunnels;
    std::istringstream lines(ip_link_output); std::string line;
    while (std::getline(lines, line)) {
        const auto first_colon = line.find(':');
        if (first_colon == std::string::npos) continue;
        const auto second_colon = line.find(':', first_colon + 1);
        if (second_colon == std::string::npos) continue;
        auto name = line.substr(first_colon + 1, second_colon - first_colon - 1);
        name.erase(0, name.find_first_not_of(" \t"));
        const auto peer_separator = name.find('@'); if (peer_separator != std::string::npos) name.erase(peer_separator);
        if (looks_like_tunnel(name)) tunnels.push_back(name);
    }
    return tunnels;
}

VpnState VpnInspector::inspect() const {
    VpnState state;
    state.nordvpn_installed = runner_.run({"rpm", "-q", "nordvpn"}).success();
    const auto links = runner_.run({"ip", "-o", "link", "show"});
    state.interface_scan_available = links.success();
    if (links.success()) state.active_tunnel_interfaces = parse_vpn_tunnel_interfaces(links.stdout_text);
    else state.diagnostic = links.stderr_text.empty() ? "could not inspect local interfaces" : links.stderr_text;
    return state;
}
} // namespace ffc
