#pragma once

#include "ffc/firewall_state.hpp"

namespace ffc {
// The landing dashboard needs the live firewall policy, but not every
// expensive cross-check. Complete collection is deferred until an assessment
// or drift view explicitly needs it.
enum class PostureCollectionDepth { Landing, Complete };

class FirewallBackend {
public:
    virtual ~FirewallBackend() = default;
    [[nodiscard]] virtual FirewallState inspect(PostureCollectionDepth depth) const = 0;
};
} // namespace ffc
