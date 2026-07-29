#pragma once

#include "ffc/security_advisories.hpp"
#include "ffc/terminal_ui.hpp"

namespace ffc {

// Keeps advisory presentation in the security domain instead of coupling it
// to public-network metadata and diagnostics rendering.
class SecurityAdvisoryRenderer {
public:
    explicit SecurityAdvisoryRenderer(TerminalUi& ui) : ui_(ui) {}
    void show(const SecurityAdvisoryReport& report) const;

private:
    TerminalUi& ui_;
};
} // namespace ffc
