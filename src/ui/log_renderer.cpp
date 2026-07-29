#include "ffc/log_renderer.hpp"

#include <iostream>

namespace ffc {
void LogRenderer::show_analysis(const LogAnalysis& analysis) const {
    ui_.section("Local log analysis");
    std::cout << "  " << ui_.muted("Explainable summary of retained ffc logs; not an attack verdict.") << '\n';
    if (!analysis.logs_available) {
        ui_.key_value("Log status", ui_.warning(analysis.diagnostic));
        return;
    }
    ui_.key_value("Retained entries", std::to_string(analysis.entries));
    ui_.key_value("Most recent event", analysis.most_recent_utc.empty() ? "unknown" : analysis.most_recent_utc);
    ui_.key_value("Warnings", analysis.warnings == 0U ? ui_.success_badge("NONE") : ui_.warning_badge(std::to_string(analysis.warnings)));
    ui_.key_value("Errors", analysis.errors == 0U ? ui_.success_badge("NONE") : ui_.danger_badge(std::to_string(analysis.errors)));
    ui_.key_value("Assessment", analysis.diagnostic.empty() ? ui_.muted("review recent activity") : ui_.muted(analysis.diagnostic));
    if (!analysis.recurring_failures.empty()) {
        ui_.section("Repeated error events");
        for (const auto& event : analysis.recurring_failures) ui_.key_value(to_string(event.channel) + ": " + event.event, ui_.danger_badge(std::to_string(event.count)));
    }
    if (!analysis.frequent_events.empty()) {
        ui_.section("Most frequent retained events");
        for (const auto& event : analysis.frequent_events) ui_.key_value(to_string(event.channel) + ": " + event.event, std::to_string(event.count));
    }
}
} // namespace ffc
