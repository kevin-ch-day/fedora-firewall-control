#pragma once

#include "ffc/firewall_backend.hpp"
#include "ffc/dashboard.hpp"

#include <string>

namespace ffc {
// Coordinates user interaction and read-only firewall inspection. Mutation
// workflows belong in separate transaction classes in later releases.
class Application {
public:
    Application(FirewallBackend& backend, Dashboard& dashboard);
    int run(int argc, char** argv);

private:
    FirewallBackend& backend_;
    Dashboard& dashboard_;
    FirewallState state_;

    void refresh();
    int run_interactive();
    int readiness_exit_code() const;
    static void print_usage();
    static std::string items_or_none(const std::vector<std::string>& items);
};
} // namespace ffc
