#pragma once

#include "ffc/dashboard.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/credentials.hpp"
#include "ffc/operating_mode.hpp"
#include "ffc/posture_inspector.hpp"

#include <string>

namespace ffc {
// Coordinates user interaction and read-only firewall inspection. Mutation
// workflows belong in separate transaction classes in later releases.
class Application {
public:
    Application(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const IpifyCredentialStore& ipify_credentials, OperatingModeStore& operating_mode, Dashboard& dashboard);
    int run(int argc, char** argv);

private:
    const PostureInspector& posture_;
    const NetworkEvidenceService& network_evidence_;
    const NetworkDiagnosticsInspector& network_diagnostics_;
    const IpifyCredentialStore& ipify_credentials_;
    OperatingModeStore& operating_mode_;
    Dashboard& dashboard_;
    FirewallState state_;

    void refresh();
    int run_interactive();
    int readiness_exit_code() const;
    static void print_usage();
};
} // namespace ffc
