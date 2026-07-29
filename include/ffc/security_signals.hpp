#pragma once

#include "ffc/command_runner.hpp"

#include <cstddef>
#include <string>

namespace ffc {
struct SecuritySignalsState {
    bool kernel_journal_available{false};
    std::size_t kernel_drop_or_reject_events{0};
    std::size_t kernel_denial_unique_sources{0};
    std::size_t kernel_denial_unique_destination_ports{0};
    bool firewalld_journal_available{false};
    std::size_t firewalld_service_events{0};
    std::string diagnostic;
};

struct KernelDenialSummary {
    std::size_t event_count{0};
    std::size_t unique_sources{0};
    std::size_t unique_destination_ports{0};
};

std::size_t count_journal_entries(const std::string& journal_output);
[[nodiscard]] KernelDenialSummary summarize_kernel_denials(const std::string& journal_output);

// Reads bounded local journal summaries. Counts are signals to investigate,
// never evidence of a particular actor or attack campaign.
class SecuritySignalsInspector {
public:
    explicit SecuritySignalsInspector(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] SecuritySignalsState inspect() const;

private:
    const CommandRunner& runner_;
};
} // namespace ffc
