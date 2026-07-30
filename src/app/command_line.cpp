#include "ffc/command_line.hpp"

namespace ffc {
namespace {
CommandLine make_command(CommandAction action) { CommandLine result; result.action = action; return result; }
} // namespace

CommandLine parse_command_line(const std::vector<std::string>& arguments) {
    if (arguments.empty()) return make_command(CommandAction::Interactive);
    if (arguments.size() == 1) {
        const auto& argument = arguments.front();
        if (argument == "--help") return make_command(CommandAction::Help);
        if (argument == "--status") return make_command(CommandAction::Status);
        if (argument == "--snapshot-json") return make_command(CommandAction::SnapshotJson);
        if (argument == "--snapshot-json-v2") return make_command(CommandAction::SnapshotJsonV2);
        if (argument == "--readiness") return make_command(CommandAction::Readiness);
        if (argument == "--listeners") return make_command(CommandAction::Listeners);
        if (argument == "--threat-assessment") return make_command(CommandAction::ThreatAssessment);
        if (argument == "--network-diagnostics") return make_command(CommandAction::NetworkDiagnostics);
        if (argument == "--security-advisories") return make_command(CommandAction::SecurityAdvisories);
        if (argument == "--network-metadata") return make_command(CommandAction::NetworkMetadata);
        if (argument == "--network-history") return make_command(CommandAction::NetworkHistory);
        if (argument == "--log-analysis") return make_command(CommandAction::LogAnalysis);
        if (argument == "--configure-ipify-key") return make_command(CommandAction::ConfigureIpifyKey);
        if (argument == "--mode") return make_command(CommandAction::Mode);
        return make_command(CommandAction::Invalid);
    }
    if (arguments.size() == 2 && arguments[0] == "--network-metadata" && arguments[1] == "--enrich") { auto result = make_command(CommandAction::NetworkMetadata); result.enrich_metadata = true; return result; }
    if (arguments.size() == 2 && arguments[0] == "--network-diagnostics" && arguments[1] == "--extended") { auto result = make_command(CommandAction::NetworkDiagnostics); result.extended_diagnostics = true; return result; }
    if (arguments.size() == 2 && arguments[0] == "--network-diagnostics" && arguments[1] == "--advanced") { auto result = make_command(CommandAction::NetworkDiagnostics); result.extended_diagnostics = true; result.advanced_diagnostics = true; return result; }
    if (arguments.size() == 2 && arguments[0] == "--mode") {
        const auto mode = parse_operating_mode(arguments[1]);
        if (!mode) return make_command(CommandAction::Invalid);
        auto result = make_command(CommandAction::Mode); result.mode_to_set = *mode; return result;
    }
    return make_command(CommandAction::Invalid);
}

std::string command_action_name(CommandAction action) {
    switch (action) {
        case CommandAction::Interactive: return "interactive";
        case CommandAction::Help: return "help";
        case CommandAction::Status: return "status";
        case CommandAction::SnapshotJson: return "snapshot-json";
        case CommandAction::SnapshotJsonV2: return "snapshot-json-v2";
        case CommandAction::Readiness: return "readiness";
        case CommandAction::Listeners: return "listeners";
        case CommandAction::ThreatAssessment: return "threat-assessment";
        case CommandAction::NetworkDiagnostics: return "network-diagnostics";
        case CommandAction::SecurityAdvisories: return "security-advisories";
        case CommandAction::NetworkMetadata: return "network-metadata";
        case CommandAction::NetworkHistory: return "network-history";
        case CommandAction::LogAnalysis: return "log-analysis";
        case CommandAction::ConfigureIpifyKey: return "configure-ipify-key";
        case CommandAction::Mode: return "mode";
        case CommandAction::Invalid: return "invalid";
    }
    return "invalid";
}
} // namespace ffc
