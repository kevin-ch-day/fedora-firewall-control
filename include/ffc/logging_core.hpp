#pragma once

#include <string>

namespace ffc {
enum class LogChannel { Operations, Audit, Security, Error };
enum class LogLevel { Info, Warning, Error };

struct LogEvent {
    LogChannel channel{LogChannel::Operations};
    LogLevel level{LogLevel::Info};
    std::string event;
    std::string detail;
};

[[nodiscard]] std::string to_string(LogChannel channel);
[[nodiscard]] std::string to_string(LogLevel level);
} // namespace ffc
