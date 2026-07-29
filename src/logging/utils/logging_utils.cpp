#include "ffc/logging_utils.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace ffc {
namespace {
bool is_ipify_key_character(unsigned char character) {
    return std::isalnum(character) != 0 || character == '_' || character == '-';
}
}

std::string sanitize_log_value(std::string_view value, std::size_t maximum_length) {
    std::string sanitized;
    sanitized.reserve(std::min(value.size(), maximum_length));
    for (std::size_t index = 0; index < value.size() && sanitized.size() < maximum_length;) {
        if (index + 3U <= value.size() && value.substr(index, 3U) == "at_") {
            std::size_t end = index + 3U;
            while (end < value.size() && is_ipify_key_character(static_cast<unsigned char>(value[end]))) ++end;
            if (end > index + 3U) {
                constexpr std::string_view redaction = "[REDACTED_IPIFY_KEY]";
                sanitized.append(redaction.substr(0, std::min(redaction.size(), maximum_length - sanitized.size())));
                index = end;
                continue;
            }
        }
        const unsigned char character = static_cast<unsigned char>(value[index++]);
        sanitized += (character < 32U || character == 127U) ? ' ' : static_cast<char>(character);
    }
    return sanitized;
}

std::string utc_log_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
    gmtime_r(&time, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::string log_file_name(LogChannel channel) { return to_string(channel) + ".log"; }

std::string format_log_event(const LogEvent& event) {
    return utc_log_timestamp() + '\t' + to_string(event.level) + '\t' + to_string(event.channel) + '\t' +
           sanitize_log_value(event.event, 96U) + '\t' + sanitize_log_value(event.detail) + '\n';
}
} // namespace ffc
