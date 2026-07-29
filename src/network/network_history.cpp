#include "ffc/network_history.hpp"

#include "ffc/network_metadata.hpp"
#include "ffc/secure_storage.hpp"

#include <algorithm>
#include <sstream>
#include <vector>

namespace ffc {
namespace {
constexpr std::size_t maximum_history_records = 512U;
constexpr std::size_t maximum_history_bytes = 256U * 1024U;

std::string history_field(std::string value) {
    for (auto &character : value) {
        if (character == '\t' || character == '\r' || character == '\n' ||
            static_cast<unsigned char>(character) < 32U || character == '\x7f')
            character = ' ';
    }
    return value;
}

std::string retain_recent_records(const std::string& content) {
    std::vector<std::string> records;
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) continue;
        records.push_back(line);
        // Reserve one record for the observation that triggers compaction.
        if (records.size() >= maximum_history_records)
            records.erase(records.begin());
    }
    std::string retained;
    for (auto record = records.rbegin(); record != records.rend(); ++record) {
        const std::size_t bytes = record->size() + 1U;
        if (retained.size() + bytes > maximum_history_bytes) break;
        retained.insert(0U, *record + '\n');
    }
    return retained;
}

std::size_t history_record_count(const std::string& content) {
    return static_cast<std::size_t>(std::count(content.begin(), content.end(), '\n'));
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
    std::string existing;
    const bool readable =
        read_private_file(file_path, existing, error, maximum_history_bytes * 4U);
    if (!readable && error != "No such file or directory" &&
        error != "storage file exceeds safe size limit") {
        result = error;
        return false;
    }
    const auto retained = readable ? retain_recent_records(existing) : std::string{};
    const bool compact = !readable || retained != existing ||
                         history_record_count(existing) >= maximum_history_records ||
                         retained.size() + record.size() > maximum_history_bytes;
    const bool written = compact
                             ? replace_private_file_atomically(file_path, retained + record, error)
                             : write_private_file(file_path, record, true, error);
    if (!written) {
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
    if (!read_private_file(file_path, content, error, maximum_history_bytes)) {
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
