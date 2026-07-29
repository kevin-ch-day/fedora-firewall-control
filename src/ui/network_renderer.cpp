#include "ffc/network_renderer.hpp"

#include "network_diagnostics_renderer.hpp"

#include <iostream>

namespace ffc {
void NetworkRenderer::show_metadata(const NetworkMetadata &metadata,
                                    const std::string &history_path) const {
    ui_.section("Public network metadata");
    ui_.key_value("Observed at",
                  metadata.observed_at_utc.empty() ? "unknown" : metadata.observed_at_utc);
    ui_.key_value("Public IP", metadata.public_ip_lookup_succeeded ? ui_.accent(metadata.public_ip)
                                                                   : ui_.warning("lookup failed"));
    ui_.key_value("Default interface",
                  metadata.default_interface.empty() ? "unknown" : metadata.default_interface);
    ui_.key_value("Default gateway",
                  metadata.default_gateway.empty() ? "unknown" : metadata.default_gateway);
    ui_.key_value("Connection profile",
                  metadata.connection_profile.empty() ? "unknown" : metadata.connection_profile);
    if (!metadata.wifi_ssid.empty()) {
        ui_.key_value("Wi-Fi SSID", metadata.wifi_ssid);
        ui_.key_value("Wi-Fi BSSID", metadata.wifi_bssid.empty() ? "unknown" : metadata.wifi_bssid);
        ui_.key_value("Wi-Fi security",
                      metadata.wifi_security.empty() ? "unknown" : metadata.wifi_security);
    }
    if (!metadata.country.empty())
        ui_.key_value("Country", metadata.country);
    if (!metadata.timezone.empty())
        ui_.key_value("Timezone", metadata.timezone);
    if (!metadata.isp.empty())
        ui_.key_value("ISP", metadata.isp);
    if (!metadata.autonomous_system.empty())
        ui_.key_value("Autonomous system", metadata.autonomous_system);
    ui_.key_value("History", history_path);
    if (!metadata.diagnostic.empty())
        ui_.key_value("Notice", ui_.warning(metadata.diagnostic));
    std::cout << "\n  " << ui_.muted("The public-IP provider received this lookup request.")
              << '\n';
}
void NetworkRenderer::show_history(const std::vector<std::string> &records,
                                   const std::string &history_path) const {
    ui_.section("Saved public network metadata");
    ui_.key_value("History", history_path);
    if (records.empty()) {
        std::cout << "  " << ui_.muted("No saved observations.") << '\n';
        return;
    }
    std::cout << "  "
              << ui_.muted("timestamp (UTC)  public IP  interface  gateway  profile  "
                           "SSID  BSSID  security  country  timezone  ISP  ASN  VPN")
              << '\n';
    for (auto record : records) {
        for (auto &character : record)
            if (character == '\t')
                character = ' ';
        std::cout << "  " << record << '\n';
    }
}
void NetworkRenderer::show_diagnostics(const NetworkDiagnostics &diagnostics) const {
    render_network_diagnostics(ui_, diagnostics);
}
} // namespace ffc
