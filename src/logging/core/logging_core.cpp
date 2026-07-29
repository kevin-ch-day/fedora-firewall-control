#include "ffc/logging_core.hpp"

namespace ffc {
std::string to_string(LogChannel channel) {
    switch (channel) {
        case LogChannel::Operations: return "operations";
        case LogChannel::Audit: return "audit";
        case LogChannel::Security: return "security";
        case LogChannel::Error: return "error";
    }
    return "operations";
}

std::string to_string(LogLevel level) {
    switch (level) {
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Error: return "ERROR";
    }
    return "ERROR";
}
} // namespace ffc
