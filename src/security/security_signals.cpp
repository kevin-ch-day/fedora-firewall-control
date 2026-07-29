#include "ffc/security_signals.hpp"

#include <sstream>
#include <set>

namespace ffc {
namespace {
constexpr std::size_t journal_limit = 200;

std::string field_value(const std::string& line, const std::string& key) {
    const auto first = line.find(key);
    if (first == std::string::npos) return {};
    const auto value_start = first + key.size();
    const auto value_end = line.find_first_of(" \t\n", value_start);
    return line.substr(value_start, value_end == std::string::npos ? std::string::npos : value_end - value_start);
}

}

bool journal_query_available(const JournalQueryStatus status) {
    return status == JournalQueryStatus::Available;
}

std::size_t count_journal_entries(const std::string& journal_output) {
    std::size_t count = 0; std::istringstream lines(journal_output); std::string line;
    while (std::getline(lines, line)) if (!line.empty() && line != "-- No entries --" && !line.starts_with("-- Boot ")) ++count;
    return count;
}

KernelDenialSummary summarize_kernel_denials(const std::string& journal_output) {
    KernelDenialSummary summary;
    std::set<std::string> sources;
    std::set<std::string> destination_ports;
    std::istringstream lines(journal_output);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.empty() || line == "-- No entries --" || line.starts_with("-- Boot ")) continue;
        ++summary.event_count;
        if (const auto source = field_value(line, "SRC="); !source.empty()) sources.insert(source);
        if (const auto port = field_value(line, "DPT="); !port.empty()) destination_ports.insert(port);
    }
    summary.unique_sources = sources.size();
    summary.unique_destination_ports = destination_ports.size();
    return summary;
}

SecuritySignalsState SecuritySignalsInspector::inspect() const {
    SecuritySignalsState state;
    const auto kernel = runner_.run({"journalctl", "-k", "--no-pager", "--since=-24h", "--grep=DROP|REJECT", "-n", "200"});
    if (kernel.success()) {
        const auto summary = summarize_kernel_denials(kernel.stdout_text);
        state.kernel_drop_or_reject_events = summary.event_count;
        state.kernel_denial_unique_sources = summary.unique_sources;
        state.kernel_denial_unique_destination_ports = summary.unique_destination_ports;
        state.kernel_journal_truncated = summary.event_count >= journal_limit;
        state.kernel_journal_status = state.kernel_journal_truncated ? JournalQueryStatus::Partial
                                                                      : JournalQueryStatus::Available;
        state.kernel_journal_available = journal_query_available(state.kernel_journal_status);
    } else {
        state.diagnostic = kernel.stderr_text.empty() ? "kernel journal query failed" : kernel.stderr_text;
    }

    const auto firewalld = runner_.run({"journalctl", "-u", "firewalld.service", "--no-pager", "--since=-24h", "-n", "200"});
    if (firewalld.success()) {
        state.firewalld_service_events = count_journal_entries(firewalld.stdout_text);
        state.firewalld_journal_truncated = state.firewalld_service_events >= journal_limit;
        state.firewalld_journal_status = state.firewalld_journal_truncated ? JournalQueryStatus::Partial
                                                                            : JournalQueryStatus::Available;
        state.firewalld_journal_available = journal_query_available(state.firewalld_journal_status);
    } else if (state.diagnostic.empty()) {
        state.diagnostic = firewalld.stderr_text.empty() ? "firewalld journal query failed" : firewalld.stderr_text;
    }
    return state;
}
} // namespace ffc
