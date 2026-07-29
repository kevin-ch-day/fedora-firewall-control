#include "test_support.hpp"

#include "ffc/command_line.hpp"
#include "ffc/credentials.hpp"
#include "ffc/operating_mode.hpp"
#include "ffc/port_intelligence.hpp"

#include <string_view>

namespace ffc::test {
void run_port_command_tests() {
    const auto ssh = identify_port_spec("22/tcp"); const auto range = identify_port_spec("8000-8010/tcp"); const auto wireguard = identify_endpoint("[::]:51820", "udp");
    expect(ssh.range == PortRange::WellKnown && ssh.likely_service == "SSH remote administration" && ssh.source == PortKnowledgeSource::Curated, "identifies curated well-known ports");
    expect(identify_port_spec("3389/TCP").likely_service == "RDP remote desktop" && identify_port_spec("1812/udp").likely_service == "RADIUS authentication" && identify_port_spec("502/tcp").likely_service == "Modbus industrial control", "normalizes and identifies registered services");
    expect(range.range_end == 8010 && range.likely_service == "port range (individual services vary)" && wireguard.range == PortRange::DynamicPrivate && wireguard.likely_service == "WireGuard", "handles ranges and dynamic port intelligence conservatively");
    const std::string_view ephemeral_port{"5353/UDP"};
    expect(identify_port_spec(ephemeral_port).likely_service == "mDNS discovery", "accepts non-owning string views for port intelligence lookups");
    expect(is_valid_ipify_api_key("at_example_key-123") && !is_valid_ipify_api_key("") && !is_valid_ipify_api_key("contains a space"), "validates Geo ipify API key format");
    expect(parse_operating_mode("hostile") == OperatingMode::HostileNetwork && !parse_operating_mode("unsafe"), "returns typed operating-mode parse results without output parameters");
    expect(command_action_name(CommandAction::ThreatAssessment) == "threat-assessment" &&
               parse_command_line({"--log-analysis"}).action == CommandAction::LogAnalysis &&
               parse_command_line({"--snapshot-json"}).action == CommandAction::SnapshotJson &&
               parse_command_line({"--network-diagnostics", "--unknown"}).action == CommandAction::Invalid,
           "parses typed commands without retaining raw arguments");
}
} // namespace ffc::test
