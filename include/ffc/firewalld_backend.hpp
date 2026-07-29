#pragma once

#include "ffc/command_runner.hpp"
#include "ffc/firewall_backend.hpp"

namespace ffc {
class FirewalldCommandBackend final : public FirewallBackend {
public:
    explicit FirewalldCommandBackend(const CommandRunner& runner) : runner_(runner) {}
    FirewallState inspect() const override;
private:
    const CommandRunner& runner_;
    CommandResult firewalld_cmd(const std::vector<std::string>& args) const;
};
} // namespace ffc
