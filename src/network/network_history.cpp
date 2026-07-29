#include "ffc/network_history.hpp"

#include "ffc/network_metadata.hpp"
#include "ffc/secure_storage.hpp"

#include <sstream>

namespace ffc {
namespace {
std::string history_field(std::string value) {
    for (auto &character : value) {
        if (character == '\t' || character == '\r' || character == '\n' ||
            static_cast<unsigned char>(character) < 32U || character == '\x7f')
            character = ' ';
    }
    return value;
}
} // namespace

std::string NetworkHistoryStore::path(std::string &error, const bool create_directory) const {
    return secure_local_path(LocalStorageArea::State, "network-history.tsv", create_directory,
                             error);
}

bool NetworkHistoryStore::append(const NetworkMetadata &metadata, const bool vpn_active,
                                 std::string &result) const {
    std::string error;
    const auto file_path = path(error, true);
    if (file_path.empty()) {
        result = error;
        return false;
    }
    const std::string record =
        history_field(metadata.observed_at_utc) + '\t' + history_field(metadata.public_ip) + '\t' +
        history_field(metadata.default_interface) + '\t' + history_field(metadata.default_gateway) +
        '\t' + history_field(metadata.connection_profile) + '\t' +
        history_field(metadata.wifi_ssid) + '\t' + history_field(metadata.wifi_bssid) + '\t' +
        history_field(metadata.wifi_security) + '\t' + history_field(metadata.country) + '\t' +
        history_field(metadata.timezone) + '\t' + history_field(metadata.isp) + '\t' +
        history_field(metadata.autonomous_system) + '\t' + (vpn_active ? "active" : "inactive") +
        '\n';
    if (!write_private_file(file_path, record, true, error)) {
        result = error;
        return false;
    }
    result = file_path;
    return true;
}

bool NetworkHistoryStore::read_recent(std::vector<std::string> &records,
                                      std::string &result) const {
    std::string error;
    const auto file_path = path(error, false);
    if (file_path.empty()) {
        result = error;
        return false;
    }
    std::string content;
    if (!read_private_file(file_path, content, error)) {
        result = error == "No such file or directory" ? "no network metadata history yet" : error;
        return false;
    }
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line))
        if (!line.empty())
            records.push_back(line);
    result = file_path;
    return true;
}
} // namespace ffc
