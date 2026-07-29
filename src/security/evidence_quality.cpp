#include "ffc/evidence_quality.hpp"
#include "ffc/text_utils.hpp"

namespace ffc {
EvidenceQualityState EvidenceQualityInspector::inspect() const {
    EvidenceQualityState state;
    const auto time_sync = runner_.run({"timedatectl", "show", "--property=NTPSynchronized", "--value"});
    state.time_sync_status_available = time_sync.success();
    if (state.time_sync_status_available) state.time_synchronized = trim_copy(time_sync.stdout_text) == "yes";
    else state.diagnostic = time_sync.stderr_text.empty() ? "time synchronization status unavailable" : time_sync.stderr_text;

    const auto journald = runner_.run({"systemctl", "is-active", "systemd-journald.service"});
    state.journald_service_available = journald.success() && trim_copy(journald.stdout_text) == "active";
    if (!state.journald_service_available && state.diagnostic.empty()) state.diagnostic = journald.stderr_text.empty() ? "systemd-journald is not active" : journald.stderr_text;
    return state;
}
} // namespace ffc
