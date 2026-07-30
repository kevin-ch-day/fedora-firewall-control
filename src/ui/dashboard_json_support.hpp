#pragma once

#include "ffc/dashboard_state.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

namespace ffc::dashboard_json_detail {

[[nodiscard]] inline std::string escape(const std::string_view value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
        case '"':
            output << "\\\"";
            break;
        case '\\':
            output << "\\\\";
            break;
        case '\b':
            output << "\\b";
            break;
        case '\f':
            output << "\\f";
            break;
        case '\n':
            output << "\\n";
            break;
        case '\r':
            output << "\\r";
            break;
        case '\t':
            output << "\\t";
            break;
        default:
            if (character < 0x20U)
                output << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<unsigned int>(character) << std::dec << std::setfill(' ');
            else
                output << static_cast<char>(character);
        }
    }
    return output.str();
}

[[nodiscard]] inline std::string quote(const std::string_view value) {
    return "\"" + escape(value) + "\"";
}

[[nodiscard]] inline std::string
iso_timestamp(const std::chrono::system_clock::time_point timestamp) {
    const auto time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm utc{};
    gmtime_r(&time, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

[[nodiscard]] constexpr std::string_view evidence_status(const ObservationStatus status) {
    switch (status) {
    case ObservationStatus::Available:
        return "available";
    case ObservationStatus::Partial:
        return "partial";
    case ObservationStatus::Unavailable:
        return "unavailable";
    }
    return "unavailable";
}

[[nodiscard]] constexpr std::string_view risk_level(const DashboardRisk risk) {
    switch (risk) {
    case DashboardRisk::Ready:
        return "ready";
    case DashboardRisk::Review:
        return "review_required";
    case DashboardRisk::Blocked:
        return "blocked";
    }
    return "review_required";
}

[[nodiscard]] constexpr std::string_view readiness(const DefconReadiness value) {
    switch (value) {
    case DefconReadiness::NotEvaluated:
        return "not_evaluated";
    case DefconReadiness::Ready:
        return "ready";
    case DefconReadiness::NotReady:
        return "not_ready";
    }
    return "not_evaluated";
}

[[nodiscard]] constexpr std::string_view severity(const FindingSeverity value) {
    switch (value) {
    case FindingSeverity::Critical:
        return "critical";
    case FindingSeverity::High:
        return "high";
    case FindingSeverity::Medium:
        return "medium";
    case FindingSeverity::Low:
        return "low";
    case FindingSeverity::Information:
        return "information";
    }
    return "information";
}

[[nodiscard]] constexpr std::string_view category(const FindingCategory value) {
    switch (value) {
    case FindingCategory::Isolation:
        return "isolation";
    case FindingCategory::Firewall:
        return "firewall_failure";
    case FindingCategory::Exposure:
        return "firewall_exposure";
    case FindingCategory::Listener:
        return "listener_exposure";
    case FindingCategory::Change:
        return "configuration_change";
    case FindingCategory::EvidenceGap:
        return "evidence_gap";
    case FindingCategory::Hygiene:
        return "hygiene";
    }
    return "hygiene";
}

[[nodiscard]] constexpr std::string_view destination(const MenuDestination value) {
    switch (value) {
    case MenuDestination::Readiness:
        return "readiness";
    case MenuDestination::Signals:
        return "signals";
    case MenuDestination::Firewall:
        return "firewall.active_openings";
    case MenuDestination::Network:
        return "network";
    case MenuDestination::Evidence:
        return "evidence";
    case MenuDestination::Settings:
        return "settings";
    case MenuDestination::Emergency:
        return "emergency";
    }
    return "readiness";
}

} // namespace ffc::dashboard_json_detail
