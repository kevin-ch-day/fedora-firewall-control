#pragma once

#include "ffc/firewall_state.hpp"

namespace ffc {
class FirewallBackend {
public:
    virtual ~FirewallBackend() = default;
    virtual FirewallState inspect() const = 0;
};
} // namespace ffc
