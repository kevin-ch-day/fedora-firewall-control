#pragma once

#include "ffc/command_runner.hpp"

#include <cstddef>
#include <string>

namespace ffc {
struct SecuritySignalsState {
    bool kernel_journal_available{false};
    std::size_t kernel_drop_or_reject_events{0};
    bool firewalld_journal_available{false};
    std::size_t firewalld_service_events{0};
    std::string diagnostic;
};

std::size_t count_journal_entries(const std::string& journal_output);

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
