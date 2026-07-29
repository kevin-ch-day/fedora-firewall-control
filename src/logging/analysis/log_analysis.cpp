#include "ffc/log_analysis.hpp"

#include "ffc/logging_utils.hpp"
#include "ffc/secure_storage.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <sstream>
#include <tuple>

namespace ffc {
namespace {
constexpr std::size_t maximum_log_bytes = 512U * 1024U;
constexpr std::size_t display_limit = 6U;

struct ParsedLogEntry {
    std::string timestamp;
    LogLevel level{LogLevel::Info};
    std::string event;
};

bool parse_level(const std::string& text, LogLevel& level) {
    if (text == "INFO") { level = LogLevel::Info; return true; }
    if (text == "WARN") { level = LogLevel::Warning; return true; }
    if (text == "ERROR") { level = LogLevel::Error; return true; }
    return false;
}

bool is_safe_event_name(const std::string& event) {
    return !event.empty() && event.size() <= 96U && std::all_of(event.begin(), event.end(), [](unsigned char character) {
        return std::isalnum(character) != 0 || character == '-' || character == '_';
    });
}

bool parse_entry(const std::string& line, LogChannel expected_channel, ParsedLogEntry& entry) {
    std::array<std::string, 5> fields;
    std::size_t field = 0;
    for (const char character : line) {
        if (character == '\t') {
            if (++field >= fields.size()) return false;
            continue;
        }
        fields[field] += character;
    }
    if (field != fields.size() - 1U || fields[0].size() != 20U || fields[2] != to_string(expected_channel) || !is_safe_event_name(fields[3])) return false;
    LogLevel level;
    if (!parse_level(fields[1], level)) return false;
    entry = {fields[0], level, fields[3]};
    return true;
}

void append_ranked(std::vector<LogEventFrequency>& output, const std::map<std::pair<LogChannel, std::string>, std::size_t>& counts, std::size_t minimum_count) {
    for (const auto& [key, count] : counts) if (count >= minimum_count) output.push_back({key.first, key.second, count});
    std::sort(output.begin(), output.end(), [](const LogEventFrequency& left, const LogEventFrequency& right) {
        return std::tie(left.count, left.event) > std::tie(right.count, right.event);
    });
    if (output.size() > display_limit) output.resize(display_limit);
}
} // namespace

LogAnalysis LocalLogAnalyzer::inspect() const {
    LogAnalysis analysis;
    std::map<std::pair<LogChannel, std::string>, std::size_t> all_events, failures;
    for (const LogChannel channel : {LogChannel::Operations, LogChannel::Audit, LogChannel::Security, LogChannel::Error}) {
        std::string error;
        const auto path = secure_local_path(LocalStorageArea::State, log_file_name(channel), false, error);
        if (path.empty()) { analysis.diagnostic = "local log storage is unavailable"; continue; }
        std::string content;
        if (!read_private_file(path, content, error, maximum_log_bytes)) {
            if (error != "No such file or directory") analysis.diagnostic = "one or more local logs could not be read safely";
            continue;
        }
        analysis.logs_available = true;
        std::istringstream lines(content);
        std::string line;
        while (std::getline(lines, line)) {
            ParsedLogEntry entry;
            if (!parse_entry(line, channel, entry)) continue;
            ++analysis.entries;
            ++all_events[{channel, entry.event}];
            if (entry.level == LogLevel::Warning) ++analysis.warnings;
            if (entry.level == LogLevel::Error) { ++analysis.errors; ++failures[{channel, entry.event}]; }
            if (entry.timestamp > analysis.most_recent_utc) analysis.most_recent_utc = entry.timestamp;
        }
    }
    append_ranked(analysis.frequent_events, all_events, 1U);
    append_ranked(analysis.recurring_failures, failures, 2U);
    if (!analysis.logs_available && analysis.diagnostic.empty()) analysis.diagnostic = "no local application logs yet";
    if (analysis.logs_available && analysis.errors == 0U && analysis.diagnostic.empty()) analysis.diagnostic = "no error-level events in retained logs";
    return analysis;
}
} // namespace ffc
