#pragma once

#include "ffc/command_line.hpp"
#include "ffc/credentials.hpp"
#include "ffc/dashboard.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/log_analysis.hpp"
#include "ffc/posture_inspector.hpp"
#include "ffc/security_advisories.hpp"

namespace ffc {
// Executes validated non-interactive commands. It owns no terminal session
// state and never receives raw argv values.
class CommandExecutor {
public:
    CommandExecutor(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const SecurityAdvisoryInspector& security_advisories, const LocalLogAnalyzer& log_analyzer, const IpifyCredentialStore& ipify_credentials, OperatingModeStore& operating_mode, Dashboard& dashboard);
    int execute(const CommandLine& command) const;

private:
    const PostureInspector& posture_;
    const NetworkEvidenceService& network_evidence_;
    const NetworkDiagnosticsInspector& network_diagnostics_;
    const SecurityAdvisoryInspector& security_advisories_;
    const LocalLogAnalyzer& log_analyzer_;
    const IpifyCredentialStore& ipify_credentials_;
    OperatingModeStore& operating_mode_;
    Dashboard& dashboard_;
};
} // namespace ffc
