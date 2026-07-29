#pragma once

#include "ffc/command_runner.hpp"

#include <string>

namespace ffc {

struct EvidenceQualityState {
    bool time_sync_status_available{false};
    bool time_synchronized{false};
    bool journald_service_available{false};
    std::string diagnostic;
};

// Checks only the local prerequisites needed to correlate event timestamps;
// it never changes time synchronization or journal configuration.
class EvidenceQualityInspector {
public:
    explicit EvidenceQualityInspector(const CommandRunner& runner) : runner_(runner) {}
    [[nodiscard]] EvidenceQualityState inspect() const;

private:
    const CommandRunner& runner_;
};

} // namespace ffc
