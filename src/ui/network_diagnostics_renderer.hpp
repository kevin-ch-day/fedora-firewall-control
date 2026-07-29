#pragma once

#include "ffc/network_diagnostics.hpp"
#include "ffc/terminal_ui.hpp"

namespace ffc {
void render_network_diagnostics(TerminalUi& ui, const NetworkDiagnostics& diagnostics);
} // namespace ffc
