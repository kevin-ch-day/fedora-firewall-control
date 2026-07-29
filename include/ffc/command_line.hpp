#pragma once

#include "ffc/operating_mode.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ffc {
enum class CommandAction {
    Interactive,
    Help,
    Status,
    Readiness,
    Listeners,
    ThreatAssessment,
    NetworkDiagnostics,
    SecurityAdvisories,
    NetworkMetadata,
    NetworkHistory,
    LogAnalysis,
    ConfigureIpifyKey,
    Mode,
    Invalid,
};

struct CommandLine {
    CommandAction action{CommandAction::Invalid};
    bool enrich_metadata{false};
    bool extended_diagnostics{false};
    bool advanced_diagnostics{false};
    std::optional<OperatingMode> mode_to_set;
};

// Parses only supported fixed commands. Argument interpretation stays outside
// Application so UI execution never needs to reason about raw argv values.
[[nodiscard]] CommandLine parse_command_line(const std::vector<std::string>& arguments);
[[nodiscard]] std::string command_action_name(CommandAction action);
} // namespace ffc
