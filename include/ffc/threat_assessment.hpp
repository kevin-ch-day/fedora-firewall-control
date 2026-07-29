#pragma once

#include "ffc/firewall_state.hpp"

#include <string>
#include <vector>

namespace ffc {

enum class ThreatFindingKind { CandidateAlert, Exposure, CoverageGap, ScopeLimit, NoAlert };

struct ThreatFinding {
    ThreatFindingKind kind{ThreatFindingKind::NoAlert};
    std::string title;
    std::string detail;
    std::string false_positive_context;
    std::string validation_step;
};

struct ThreatAssessment {
    std::vector<ThreatFinding> findings;
    std::vector<std::string> verdict_rules;
};

// Produces a bounded, evidence-oriented review. It intentionally never claims
// a true positive, false positive, true negative, or false negative because
// those verdicts require ground truth outside this host snapshot.
[[nodiscard]] ThreatAssessment assess_threat_evidence(const FirewallState& state);
[[nodiscard]] std::string to_string(ThreatFindingKind kind);

} // namespace ffc
