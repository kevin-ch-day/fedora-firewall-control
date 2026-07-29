#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace ffc {
enum class PortRange { WellKnown, Registered, DynamicPrivate, Unknown };
enum class PortKnowledgeSource { Curated, SystemServiceDatabase, RangeOnly };

struct PortIntel {
    std::optional<unsigned short> port;
    std::optional<unsigned short> range_end;
    std::string protocol;
    PortRange range{PortRange::Unknown};
    std::string likely_service;
    PortKnowledgeSource source{PortKnowledgeSource::RangeOnly};
};

// Conventional port knowledge for exposure review. A label identifies a
// typical assignment, never verifies the actual service or process.
[[nodiscard]] PortIntel identify_port(unsigned short port, std::string_view protocol);
[[nodiscard]] PortIntel identify_port_spec(std::string_view port_spec);
[[nodiscard]] PortIntel identify_endpoint(std::string_view endpoint, std::string_view protocol);
[[nodiscard]] std::string port_range_label(PortRange range);
[[nodiscard]] std::string port_knowledge_source_label(PortKnowledgeSource source);
[[nodiscard]] std::string port_intel_label(const PortIntel& intel);
} // namespace ffc
