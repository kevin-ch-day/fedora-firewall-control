#pragma once

#include "ffc/dashboard.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/logging_engine.hpp"
#include "ffc/log_analysis.hpp"
#include "ffc/posture_inspector.hpp"
#include "ffc/security_advisories.hpp"

namespace ffc {
// Owns the refreshable state and keyboard loop of the terminal dashboard.
class InteractiveSession {
public:
    InteractiveSession(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const SecurityAdvisoryInspector& security_advisories, const LocalLogAnalyzer& log_analyzer, Dashboard& dashboard, const LoggingEngine& logger);
    int run();

private:
    const PostureInspector& posture_;
    const NetworkEvidenceService& network_evidence_;
    const NetworkDiagnosticsInspector& network_diagnostics_;
    const SecurityAdvisoryInspector& security_advisories_;
    const LocalLogAnalyzer& log_analyzer_;
    Dashboard& dashboard_;
    const LoggingEngine& logger_;
    FirewallState state_;

    void refresh();
    void record_action(const char* action, LogChannel channel = LogChannel::Audit) const;
};
} // namespace ffc
