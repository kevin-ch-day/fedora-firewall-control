#include "ffc/evidence_quality.hpp"

#include <algorithm>
#include <cctype>

namespace ffc {
namespace {
std::string trimmed(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char character) { return std::isspace(character) != 0; });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char character) { return std::isspace(character) != 0; }).base();
    return first >= last ? std::string{} : std::string(first, last);
}
} // namespace

EvidenceQualityState EvidenceQualityInspector::inspect() const {
    EvidenceQualityState state;
    const auto time_sync = runner_.run({"timedatectl", "show", "--property=NTPSynchronized", "--value"});
    state.time_sync_status_available = time_sync.success();
    if (state.time_sync_status_available) state.time_synchronized = trimmed(time_sync.stdout_text) == "yes";
    else state.diagnostic = time_sync.stderr_text.empty() ? "time synchronization status unavailable" : time_sync.stderr_text;

    const auto journald = runner_.run({"systemctl", "is-active", "systemd-journald.service"});
    state.journald_service_available = journald.success() && trimmed(journald.stdout_text) == "active";
    if (!state.journald_service_available && state.diagnostic.empty()) state.diagnostic = journald.stderr_text.empty() ? "systemd-journald is not active" : journald.stderr_text;
    return state;
}
} // namespace ffc
