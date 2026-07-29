#pragma once

#include "ffc/logging_core.hpp"

#include <string>
#include <string_view>

namespace ffc {
// Converts untrusted text to a bounded, single-line value and redacts
// ipify-style API keys before anything is persisted.
[[nodiscard]] std::string sanitize_log_value(std::string_view value, std::size_t maximum_length = 512U);
[[nodiscard]] std::string utc_log_timestamp();
[[nodiscard]] std::string log_file_name(LogChannel channel);
[[nodiscard]] std::string format_log_event(const LogEvent& event);
} // namespace ffc
