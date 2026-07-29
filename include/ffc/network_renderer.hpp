#pragma once

#include "ffc/network_diagnostics.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/terminal_ui.hpp"

#include <string>
#include <vector>

namespace ffc {
class NetworkRenderer {
public:
    explicit NetworkRenderer(TerminalUi& ui) : ui_(ui) {}
    void show_metadata(const NetworkMetadata& metadata, const std::string& history_path) const;
    void show_history(const std::vector<std::string>& records, const std::string& history_path) const;
    void show_diagnostics(const NetworkDiagnostics& diagnostics) const;

private:
    TerminalUi& ui_;
};
} // namespace ffc
