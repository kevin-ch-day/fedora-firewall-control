#pragma once

#include "ffc/command_runner.hpp"
#include "ffc/credentials.hpp"

#include <string>

namespace ffc {
struct NetworkMetadata {
    std::string observed_at_utc;
    std::string public_ip;
    std::string default_gateway;
    std::string default_interface;
    std::string connection_profile;
    std::string wifi_ssid;
    std::string wifi_bssid;
    std::string wifi_security;
    std::string country;
    std::string timezone;
    std::string isp;
    std::string autonomous_system;
    bool public_ip_lookup_succeeded{false};
    std::string diagnostic;
};

NetworkMetadata parse_default_route(const std::string& route_output);
bool is_valid_ip_address(const std::string& candidate);

// Explicit external lookup only. The selected provider receives the caller's
// public IP and request time; this inspector is never run during a normal scan.
class NetworkMetadataInspector {
public:
    NetworkMetadataInspector(const CommandRunner& runner, const IpifyCredentialStore& credentials) : runner_(runner), credentials_(credentials) {}
    [[nodiscard]] NetworkMetadata inspect(bool enrich) const;

private:
    const CommandRunner& runner_;
    const IpifyCredentialStore& credentials_;
};

} // namespace ffc
