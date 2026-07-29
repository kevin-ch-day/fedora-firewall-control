#pragma once

#include "ffc/logging_core.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace ffc {
struct LogEventFrequency {
    LogChannel channel{LogChannel::Operations};
    std::string event;
    std::size_t count{0};
};

struct LogAnalysis {
    bool logs_available{false};
    std::size_t entries{0};
    std::size_t warnings{0};
    std::size_t errors{0};
    std::string most_recent_utc;
    std::vector<LogEventFrequency> frequent_events;
    std::vector<LogEventFrequency> recurring_failures;
    std::string diagnostic;
};

// Produces bounded, local, explainable summaries of ffc's own structured
// logs. It does not inspect packet data or infer attacker identity.
class LocalLogAnalyzer {
public:
    [[nodiscard]] LogAnalysis inspect() const;
};
} // namespace ffc
