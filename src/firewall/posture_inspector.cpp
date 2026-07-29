#include "ffc/posture_inspector.hpp"

namespace ffc {
FirewallState DefensivePostureCollector::inspect() const {
    auto state = firewall_.inspect();
    state.operating_mode = operating_mode_.load();
    state.network_manager = network_manager_.inspect();
    state.vpn = vpn_.inspect();
    state.sockets = sockets_.inspect();
    state.security_signals = security_signals_.inspect();
    state.evidence_quality = evidence_quality_.inspect();

    if (!state.network_manager.available) state.errors.push_back("NetworkManager status unavailable: " + state.network_manager.diagnostic);
    if (!state.vpn.interface_scan_available) state.errors.push_back("VPN tunnel scan unavailable: " + state.vpn.diagnostic);
    if (!state.sockets.available) state.errors.push_back("listener scan unavailable: " + state.sockets.diagnostic);
    if (!state.security_signals.kernel_journal_available && !state.security_signals.firewalld_journal_available) state.errors.push_back("security journal signals unavailable: " + state.security_signals.diagnostic);
    if (!state.evidence_quality.time_sync_status_available || !state.evidence_quality.journald_service_available) state.errors.push_back("evidence-quality check incomplete: " + state.evidence_quality.diagnostic);
    return state;
}
} // namespace ffc
