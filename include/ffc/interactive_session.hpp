#pragma once

#include "ffc/dashboard.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/posture_inspector.hpp"
#include "ffc/security_advisories.hpp"

namespace ffc {
// Owns the refreshable state and keyboard loop of the terminal dashboard.
class InteractiveSession {
public:
    InteractiveSession(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const SecurityAdvisoryInspector& security_advisories, Dashboard& dashboard);
    int run();

private:
    const PostureInspector& posture_;
    const NetworkEvidenceService& network_evidence_;
    const NetworkDiagnosticsInspector& network_diagnostics_;
    const SecurityAdvisoryInspector& security_advisories_;
    Dashboard& dashboard_;
    FirewallState state_;

    void refresh();
};
} // namespace ffc
