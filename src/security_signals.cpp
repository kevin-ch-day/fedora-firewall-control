#include "ffc/security_signals.hpp"

#include <sstream>

namespace ffc {
namespace {
bool no_entries(const std::string& output) { return output.find("-- No entries --") != std::string::npos; }
}

std::size_t count_journal_entries(const std::string& journal_output) {
    std::size_t count = 0; std::istringstream lines(journal_output); std::string line;
    while (std::getline(lines, line)) if (!line.empty() && line != "-- No entries --" && !line.starts_with("-- Boot ")) ++count;
    return count;
}

SecuritySignalsState SecuritySignalsInspector::inspect() const {
    SecuritySignalsState state;
    const auto kernel = runner_.run({"journalctl", "-k", "--no-pager", "--since=-24h", "--grep=DROP|REJECT", "-n", "200"});
    state.kernel_journal_available = kernel.success() || no_entries(kernel.stdout_text);
    if (state.kernel_journal_available) state.kernel_drop_or_reject_events = count_journal_entries(kernel.stdout_text);
    else state.diagnostic = kernel.stderr_text.empty() ? "kernel journal query failed" : kernel.stderr_text;

    const auto firewalld = runner_.run({"journalctl", "-u", "firewalld.service", "--no-pager", "--since=-24h", "-n", "200"});
    state.firewalld_journal_available = firewalld.success() || no_entries(firewalld.stdout_text);
    if (state.firewalld_journal_available) state.firewalld_service_events = count_journal_entries(firewalld.stdout_text);
    else if (state.diagnostic.empty()) state.diagnostic = firewalld.stderr_text.empty() ? "firewalld journal query failed" : firewalld.stderr_text;
    return state;
}
} // namespace ffc
