#pragma once

#include "ffc/dashboard.hpp"
#include "ffc/network_diagnostics.hpp"
#include "ffc/network_evidence.hpp"
#include "ffc/logging_engine.hpp"
#include "ffc/log_analysis.hpp"
#include "ffc/posture_inspector.hpp"
#include "ffc/security_advisories.hpp"

#include <string_view>

namespace ffc {
// Owns the refreshable state and keyboard loop of the terminal dashboard.
class InteractiveSession {
  public:
    InteractiveSession(const PostureInspector &posture,
                       const NetworkEvidenceService &network_evidence,
                       const NetworkDiagnosticsInspector &network_diagnostics,
                       const SecurityAdvisoryInspector &security_advisories,
                       const LocalLogAnalyzer &log_analyzer, Dashboard &dashboard,
                       const LoggingEngine &logger);
    int run();

  private:
    const PostureInspector &posture_;
    const NetworkEvidenceService &network_evidence_;
    const NetworkDiagnosticsInspector &network_diagnostics_;
    const SecurityAdvisoryInspector &security_advisories_;
    const LocalLogAnalyzer &log_analyzer_;
    Dashboard &dashboard_;
    const LoggingEngine &logger_;
    FirewallState state_;

    void refresh(PostureCollectionDepth depth = PostureCollectionDepth::Landing);
    void record_action(std::string_view action, LogChannel channel = LogChannel::Audit) const;
    [[nodiscard]] bool handle_firewall_selection(std::string_view choice);
    [[nodiscard]] bool handle_network_selection(std::string_view choice);
    [[nodiscard]] bool handle_security_selection(std::string_view choice);
    void report_invalid_selection() const;
};
} // namespace ffc
