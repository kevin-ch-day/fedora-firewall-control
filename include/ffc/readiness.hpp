#pragma once

#include "ffc/firewall_state.hpp"

#include <string>
#include <vector>

namespace ffc {
enum class CheckLevel { Pass, Warn, Fail, Info };
struct ReadinessCheck { std::string label; CheckLevel level; std::string detail; };
std::vector<ReadinessCheck> assess_readiness(const FirewallState& state);
std::string to_string(CheckLevel level);
} // namespace ffc
