#include "ffc/posture_inspector.hpp"

namespace ffc {
FirewallState DefensivePostureCollector::inspect(const PostureCollectionDepth depth) const {
    auto state = firewall_.inspect(depth);
    const auto operating_mode = operating_mode_.load();
    state.operating_mode = operating_mode.mode;
    state.operating_mode_status = operating_mode.status;
    state.operating_mode_diagnostic = operating_mode.diagnostic;
    state.vpn = vpn_.inspect();
    state.sockets = sockets_.inspect();
    state.security_signals = security_signals_.inspect();
    // The landing view displays physical-device context. Collect this small,
    // local read once at every depth so it never presents missing
    // NetworkManager evidence as a firewall-derived path assertion.
    state.network_manager = network_manager_.inspect();

    if (depth == PostureCollectionDepth::Complete) {
        state.evidence_quality = evidence_quality_.inspect();
        if (!state.evidence_quality.journald_service_available) {
            if (state.security_signals.kernel_journal_status == JournalQueryStatus::Available) {
                state.security_signals.kernel_journal_status = JournalQueryStatus::Partial;
                state.security_signals.kernel_journal_available = false;
            }
            if (state.security_signals.firewalld_journal_status == JournalQueryStatus::Available) {
                state.security_signals.firewalld_journal_status = JournalQueryStatus::Partial;
                state.security_signals.firewalld_journal_available = false;
            }
            state.errors.push_back("journald service availability is not confirmed; journal signals "
                                   "are treated as partial evidence");
        }
    }

    if (!state.network_manager.available) state.errors.push_back("NetworkManager device inventory unavailable: " + state.network_manager.diagnostic);
    if (!state.vpn.interface_scan_available) state.errors.push_back("VPN tunnel scan unavailable: " + state.vpn.diagnostic);
    if (!state.sockets.available) state.errors.push_back("listener scan unavailable: " + state.sockets.diagnostic);
    if (state.operating_mode_status == OperatingModeLoadStatus::Invalid)
        state.errors.push_back(state.operating_mode_diagnostic);
    if (!state.security_signals.kernel_journal_available && !state.security_signals.firewalld_journal_available) state.errors.push_back("security journal signals unavailable: " + state.security_signals.diagnostic);
    if (depth == PostureCollectionDepth::Complete && (!state.evidence_quality.time_sync_status_available || !state.evidence_quality.journald_service_available)) state.errors.push_back("evidence-quality check incomplete: " + state.evidence_quality.diagnostic);
    return state;
}
} // namespace ffc
