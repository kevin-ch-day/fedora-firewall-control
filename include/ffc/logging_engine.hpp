#pragma once

#include "ffc/logging_core.hpp"

#include <string>

namespace ffc {
// Persists structured, owner-only local logs. Logging failures never change a
// firewall decision or command result; callers may inspect the returned status.
class LoggingEngine {
public:
    bool record(const LogEvent& event, std::string* error = nullptr) const;
};
} // namespace ffc
