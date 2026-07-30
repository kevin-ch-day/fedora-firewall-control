#pragma once

#include "ffc/dashboard_state.hpp"

#include <string>

namespace ffc {

// Serializes the transport-neutral snapshot for local automation. It performs
// no collection and never opens a listener or invokes a shell.
[[nodiscard]] std::string serialize_dashboard_snapshot_json(const DashboardSnapshot& snapshot);

// Parallel structured contract for focused firewall and exposure workflows.
// V1 remains available unchanged while consumers migrate deliberately.
[[nodiscard]] std::string serialize_dashboard_snapshot_json_v2(const DashboardSnapshot& snapshot);

} // namespace ffc
