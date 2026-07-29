#include "ffc/network_metadata.hpp"
#include "ffc/secure_storage.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <regex>
#include <sstream>

namespace ffc {
namespace {
std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    value.erase(0, first); value.erase(value.find_last_not_of(" \t\r\n") + 1); return value;
}
std::string utc_now() {
    const auto now = std::chrono::system_clock::now(); const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{}; gmtime_r(&time, &utc); std::ostringstream output; output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ"); return output.str();
}
std::vector<std::string> split_escaped_colons(const std::string& line) {
    std::vector<std::string> fields; std::string field; bool escaped = false;
    for (const char character : line) {
        if (escaped) { field += character; escaped = false; }
        else if (character == '\\') escaped = true;
        else if (character == ':') { fields.push_back(field); field.clear(); }
        else field += character;
    }
    if (escaped) field += '\\';
    fields.push_back(field);
    return fields;
}
std::string json_string(const std::string& json, const std::string& name) {
    const std::regex pattern("\\\"" + name + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\""); std::smatch match;
    return std::regex_search(json, match, pattern) ? match[1].str() : std::string{};
}
std::string json_number(const std::string& json, const std::string& name) {
    const std::regex pattern("\\\"" + name + "\\\"\\s*:\\s*([0-9]+)"); std::smatch match;
    return std::regex_search(json, match, pattern) ? match[1].str() : std::string{};
}
std::string history_field(std::string value) {
    for (auto& character : value) if (character == '\t' || character == '\r' || character == '\n' || static_cast<unsigned char>(character) < 32U || character == '\x7f') character = ' ';
    return value;
}
}

NetworkMetadata parse_default_route(const std::string& route_output) {
    NetworkMetadata metadata;
    std::istringstream lines(route_output); std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line); std::vector<std::string> values; std::string value;
        while (fields >> value) values.push_back(value);
        if (values.empty() || values.front() != "default") continue;
        for (size_t index = 0; index + 1 < values.size(); ++index) {
            if (values[index] == "via") metadata.default_gateway = values[index + 1];
            if (values[index] == "dev") metadata.default_interface = values[index + 1];
        }
        break;
    }
    return metadata;
}

bool is_valid_ip_address(const std::string& candidate) {
    in_addr ipv4{}; in6_addr ipv6{};
    return inet_pton(AF_INET, candidate.c_str(), &ipv4) == 1 || inet_pton(AF_INET6, candidate.c_str(), &ipv6) == 1;
}

NetworkMetadata NetworkMetadataInspector::inspect(bool enrich) const {
    const auto route = runner_.run({"ip", "route", "show", "default"});
    NetworkMetadata metadata = route.success() ? parse_default_route(route.stdout_text) : NetworkMetadata{};
    metadata.observed_at_utc = utc_now();
    if (!route.success()) metadata.diagnostic = route.stderr_text.empty() ? "default-route query failed" : route.stderr_text;

    const auto devices = runner_.run({"nmcli", "--terse", "--escape", "yes", "--fields", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"});
    if (devices.success()) {
        std::istringstream lines(devices.stdout_text); std::string line;
        while (std::getline(lines, line)) {
            const auto fields = split_escaped_colons(line);
            if (fields.size() >= 4 && fields[0] == metadata.default_interface) metadata.connection_profile = fields[3];
        }
    }
    const auto wifi = runner_.run({"nmcli", "--terse", "--escape", "yes", "--fields", "IN-USE,SSID,BSSID,SECURITY", "device", "wifi", "list", "--rescan", "no"});
    if (wifi.success()) {
        std::istringstream lines(wifi.stdout_text); std::string line;
        while (std::getline(lines, line)) {
            const auto fields = split_escaped_colons(line);
            if (fields.size() >= 4 && (fields[0] == "yes" || fields[0] == "*")) { metadata.wifi_ssid = fields[1]; metadata.wifi_bssid = fields[2]; metadata.wifi_security = fields[3]; break; }
        }
    }

    const auto public_ip = runner_.run({"curl", "--fail", "--silent", "--show-error", "--max-time", "5", "https://api64.ipify.org"});
    const auto candidate = trim(public_ip.stdout_text);
    if (public_ip.success() && is_valid_ip_address(candidate)) { metadata.public_ip = candidate; metadata.public_ip_lookup_succeeded = true; }
    else {
        const auto detail = public_ip.stderr_text.empty() ? "public IP response was invalid" : trim(public_ip.stderr_text);
        metadata.diagnostic += (metadata.diagnostic.empty() ? "" : "; ") + detail;
    }
    if (!enrich) return metadata;
    const std::string key = credentials_.load();
    if (key.empty()) { metadata.diagnostic += (metadata.diagnostic.empty() ? "" : "; ") + std::string("configure an ipify key or set FFC_IPIFY_API_KEY to use enrichment"); return metadata; }
    const auto enrichment = runner_.run_with_input({"curl", "--fail", "--silent", "--show-error", "--max-time", "8", "--config", "-"}, "url = \"https://geo.ipify.org/api/v2/country?apiKey=" + key + "\"\n");
    if (!enrichment.success()) { metadata.diagnostic += (metadata.diagnostic.empty() ? "" : "; ") + (enrichment.stderr_text.empty() ? "geolocation enrichment failed" : trim(enrichment.stderr_text)); return metadata; }
    metadata.country = json_string(enrichment.stdout_text, "country");
    metadata.timezone = json_string(enrichment.stdout_text, "timezone");
    metadata.isp = json_string(enrichment.stdout_text, "isp");
    const auto asn = json_number(enrichment.stdout_text, "asn"); const auto as_name = json_string(enrichment.stdout_text, "name");
    metadata.autonomous_system = asn.empty() ? as_name : "AS" + asn + (as_name.empty() ? "" : " " + as_name);
    return metadata;
}

std::string NetworkHistoryStore::path(std::string& error, bool create_directory) const {
    return secure_local_path(LocalStorageArea::State, "network-history.tsv", create_directory, error);
}

bool NetworkHistoryStore::append(const NetworkMetadata& metadata, bool vpn_active, std::string& result) const {
    std::string error; const auto file_path = path(error, true); if (file_path.empty()) { result = error; return false; }
    const std::string record = history_field(metadata.observed_at_utc) + '\t' + history_field(metadata.public_ip) + '\t' + history_field(metadata.default_interface) + '\t' + history_field(metadata.default_gateway) + '\t' + history_field(metadata.connection_profile) + '\t' + history_field(metadata.wifi_ssid) + '\t' + history_field(metadata.wifi_bssid) + '\t' + history_field(metadata.wifi_security) + '\t' + history_field(metadata.country) + '\t' + history_field(metadata.timezone) + '\t' + history_field(metadata.isp) + '\t' + history_field(metadata.autonomous_system) + '\t' + (vpn_active ? "active" : "inactive") + '\n';
    if (!write_private_file(file_path, record, true, error)) { result = error; return false; }
    result = file_path; return true;
}

bool NetworkHistoryStore::read_recent(std::vector<std::string>& records, std::string& result) const {
    std::string error; const auto file_path = path(error, false); if (file_path.empty()) { result = error; return false; }
    std::string content;
    if (!read_private_file(file_path, content, error)) { result = error == "No such file or directory" ? "no network metadata history yet" : error; return false; }
    std::istringstream input(content); std::string line; while (std::getline(input, line)) if (!line.empty()) records.push_back(line);
    result = file_path; return true;
}
} // namespace ffc
