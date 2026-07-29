#pragma once

#include <optional>
#include <string_view>

namespace ffc::port_catalog {

// Secondary catalogue for modern infrastructure and observability services.
// The primary catalogue remains in port_intelligence.cpp while it is gradually
// migrated; callers use this interface so its storage can change safely.
[[nodiscard]] std::optional<std::string_view> find_service(std::string_view protocol, unsigned short port);

// Conventional service ranges are deliberately narrow. They are used only
// after an exact match has failed, and still identify a likely use, not proof.
[[nodiscard]] std::optional<std::string_view> find_service_range(std::string_view protocol, unsigned short port);

} // namespace ffc::port_catalog
