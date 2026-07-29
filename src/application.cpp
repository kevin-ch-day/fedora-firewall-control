#include "ffc/application.hpp"

#include "ffc/readiness.hpp"

#include <iostream>

namespace ffc {
Application::Application(FirewallBackend& backend, Dashboard& dashboard) : backend_(backend), dashboard_(dashboard) {}

void Application::refresh() { state_ = backend_.inspect(); }

int Application::readiness_exit_code() const {
    bool warned = false;
    for (const auto& check : assess_readiness(state_)) {
        if (check.level == CheckLevel::Fail) return 2;
        if (check.level == CheckLevel::Warn) warned = true;
    }
    return warned ? 1 : 0;
}

void Application::print_usage() {
    std::cout << "Usage: ffc [--status | --readiness | --help]\n\n"
              << "Without an option, opens the interactive read-only dashboard.\n"
              << "  --status     Print firewall posture and exposure summary.\n"
              << "  --readiness  Print readiness checks (exit: 0 pass, 1 warning, 2 fail).\n"
              << "  --help       Show this help.\n";
}

int Application::run_interactive() {
    std::string choice;
    do {
        dashboard_.show_menu(state_);
        if (!std::getline(std::cin, choice) || choice == "0") break;
        if (choice == "r" || choice == "R") { refresh(); continue; }
        dashboard_.show_detail_header();
        if (choice == "1") dashboard_.show_status(state_);
        else if (choice == "2") dashboard_.show_zones(state_, "Zones", ZoneView::All);
        else if (choice == "3") dashboard_.show_zones(state_, "Interfaces and zone assignments", ZoneView::Interfaces);
        else if (choice == "4") dashboard_.show_zones(state_, "Allowed services", ZoneView::Services);
        else if (choice == "5") dashboard_.show_zones(state_, "Explicit open ports", ZoneView::Ports);
        else if (choice == "6") dashboard_.show_zones(state_, "Rich rules", ZoneView::RichRules);
        else if (choice == "7") dashboard_.show_zones(state_, "Forwarding and masquerading", ZoneView::Routing);
        else if (choice == "8") dashboard_.show_zones(state_, "Runtime/permanent differences", ZoneView::Drift);
        else if (choice == "9") dashboard_.show_readiness(state_);
        else dashboard_.show_invalid_selection();
        dashboard_.pause();
    } while (true);
    dashboard_.show_goodbye();
    return 0;
}

int Application::run(int argc, char** argv) {
    if (argc > 2) { print_usage(); return 2; }
    if (argc == 2 && std::string(argv[1]) == "--help") { print_usage(); return 0; }
    if (argc == 2 && std::string(argv[1]) != "--status" && std::string(argv[1]) != "--readiness") { print_usage(); return 2; }
    refresh();
    if (argc == 2 && std::string(argv[1]) == "--status") { dashboard_.show_status(state_); dashboard_.show_overview(state_); return state_.installed ? 0 : 2; }
    if (argc == 2 && std::string(argv[1]) == "--readiness") { dashboard_.show_readiness(state_); return readiness_exit_code(); }
    return run_interactive();
}
} // namespace ffc
