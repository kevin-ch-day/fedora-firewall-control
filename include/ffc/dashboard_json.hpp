#pragma once

#include "ffc/dashboard_state.hpp"

#include <string>

namespace ffc {

// Serializes the transport-neutral snapshot for local automation. It performs
// no collection and never opens a listener or invokes a shell.
[[nodiscard]] std::string serialize_dashboard_snapshot_json(const DashboardSnapshot& snapshot);

} // namespace ffc
