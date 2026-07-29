#pragma once

#include "ffc/log_analysis.hpp"
#include "ffc/terminal_ui.hpp"

namespace ffc {
class LogRenderer {
public:
    explicit LogRenderer(TerminalUi& ui) : ui_(ui) {}
    void show_analysis(const LogAnalysis& analysis) const;

private:
    TerminalUi& ui_;
};
} // namespace ffc
