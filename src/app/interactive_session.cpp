#include "ffc/interactive_session.hpp"

#include <iostream>

namespace ffc {
InteractiveSession::InteractiveSession(const PostureInspector& posture, const NetworkEvidenceService& network_evidence, const NetworkDiagnosticsInspector& network_diagnostics, const SecurityAdvisoryInspector& security_advisories, Dashboard& dashboard)
    : posture_(posture), network_evidence_(network_evidence), network_diagnostics_(network_diagnostics), security_advisories_(security_advisories), dashboard_(dashboard) {}

void InteractiveSession::refresh() { state_ = posture_.inspect(); }

int InteractiveSession::run() {
    refresh(); std::string choice;
    do {
        dashboard_.show_menu(state_);
        if (!std::getline(std::cin, choice) || choice == "0") break;
        if (choice == "r" || choice == "R") { refresh(); continue; }
        if (choice == "m" || choice == "M") { const auto capture = network_evidence_.capture(false, !state_.vpn.active_tunnel_interfaces.empty()); dashboard_.show_detail_header(); dashboard_.show_network_metadata(capture.metadata, capture.history_status()); dashboard_.pause(); continue; }
        if (choice == "h" || choice == "H") { const auto history = network_evidence_.read_history(); dashboard_.show_detail_header(); dashboard_.show_network_history(history.records, history.display_status()); dashboard_.pause(); continue; }
        if (choice == "d" || choice == "D") { dashboard_.show_detail_header(); dashboard_.show_network_diagnostics(network_diagnostics_.inspect()); dashboard_.pause(); continue; }
        if (choice == "s" || choice == "S") { dashboard_.show_detail_header(); dashboard_.show_security_advisories(security_advisories_.inspect()); dashboard_.pause(); continue; }
        dashboard_.show_detail_header();
        if (choice == "1") dashboard_.show_status(state_);
        else if (choice == "2") dashboard_.show_zones(state_, "Zones", ZoneView::All);
        else if (choice == "3") dashboard_.show_zones(state_, "Interfaces and zone assignments", ZoneView::Interfaces);
        else if (choice == "4") dashboard_.show_zones(state_, "Allowed services", ZoneView::Services);
        else if (choice == "5") dashboard_.show_zones(state_, "Explicit open ports", ZoneView::Ports);
        else if (choice == "6") dashboard_.show_zones(state_, "Rich rules", ZoneView::RichRules);
        else if (choice == "7") dashboard_.show_zones(state_, "Intra-zone forwarding and masquerading", ZoneView::Routing);
        else if (choice == "8") dashboard_.show_zones(state_, "Runtime/permanent differences", ZoneView::Drift);
        else if (choice == "9") dashboard_.show_readiness(state_);
        else if (choice == "l" || choice == "L") dashboard_.show_listeners(state_);
        else if (choice == "t" || choice == "T") dashboard_.show_threat_assessment(state_);
        else dashboard_.show_invalid_selection();
        dashboard_.pause();
    } while (true);
    dashboard_.show_goodbye(); return 0;
}
} // namespace ffc
