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
        if (argument == "--readiness") return make_command(CommandAction::Readiness);
        if (argument == "--listeners") return make_command(CommandAction::Listeners);
        if (argument == "--threat-assessment") return make_command(CommandAction::ThreatAssessment);
        if (argument == "--network-diagnostics") return make_command(CommandAction::NetworkDiagnostics);
        if (argument == "--security-advisories") return make_command(CommandAction::SecurityAdvisories);
        if (argument == "--network-metadata") return make_command(CommandAction::NetworkMetadata);
        if (argument == "--network-history") return make_command(CommandAction::NetworkHistory);
        if (argument == "--configure-ipify-key") return make_command(CommandAction::ConfigureIpifyKey);
        if (argument == "--mode") return make_command(CommandAction::Mode);
        return make_command(CommandAction::Invalid);
    }
    if (arguments.size() == 2 && arguments[0] == "--network-metadata" && arguments[1] == "--enrich") { auto result = make_command(CommandAction::NetworkMetadata); result.enrich_metadata = true; return result; }
    if (arguments.size() == 2 && arguments[0] == "--mode") {
        OperatingMode mode;
        if (!parse_operating_mode(arguments[1], mode)) return make_command(CommandAction::Invalid);
        auto result = make_command(CommandAction::Mode); result.mode_to_set = mode; return result;
    }
    return make_command(CommandAction::Invalid);
}
} // namespace ffc
