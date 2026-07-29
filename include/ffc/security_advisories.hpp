#pragma once

#include "ffc/command_runner.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace ffc {
struct SecurityAdvisoryReport {
    bool dnf_available{true};
    bool query_succeeded{false};
    std::size_t advisory_count{0};
    std::vector<std::string> cves;
    std::string diagnostic;
};

// Performs an explicit, read-only DNF5 advisory query for available security
// updates affecting the local network and security stack. It never installs,
// upgrades, or changes repository configuration.
class VulnerabilityAdvisoryCollector {
public:
    explicit VulnerabilityAdvisoryCollector(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] SecurityAdvisoryReport inspect() const;

private:
    const CommandRunner& runner_;
};
using SecurityAdvisoryInspector = VulnerabilityAdvisoryCollector; // Compatibility name for early integrations.
} // namespace ffc
