#include "ffc/security_advisory_renderer.hpp"

#include <algorithm>
#include <iostream>

namespace ffc {
namespace {
std::string display_safe_detail(std::string detail) {
    for (auto &character : detail) {
        if (static_cast<unsigned char>(character) < 32U || character == '\x7f')
            character = ' ';
    }
    if (detail.size() > 240U)
        detail.resize(240U);
    return detail;
}

std::string visible_cves(const std::vector<std::string> &cves) {
    constexpr std::size_t cve_limit = 20U;
    std::string result;
    for (std::size_t index = 0; index < std::min(cves.size(), cve_limit); ++index) {
        result += (result.empty() ? "" : ", ") + cves[index];
    }
    if (cves.size() > cve_limit)
        result += " … (" + std::to_string(cves.size() - cve_limit) + " more)";
    return result;
}
} // namespace

void SecurityAdvisoryRenderer::show(const SecurityAdvisoryReport &report) const {
    ui_.section("Available security advisories");
    std::cout << "  "
              << ui_.muted("Explicit DNF5 query only; no packages, repositories, "
                           "or firewall settings are changed.")
              << '\n';
    if (!report.dnf_available) {
        std::cout << "  " << ui_.danger_badge("DNF5 UNAVAILABLE") << " "
                  << ui_.warning(report.diagnostic) << '\n';
        return;
    }
    if (!report.query_succeeded) {
        std::cout << "  " << ui_.warning_badge("QUERY FAILED") << " "
                  << ui_.warning(display_safe_detail(report.diagnostic)) << '\n';
        return;
    }

    ui_.key_value("Available security advisories",
                  report.advisory_count == 0U
                      ? ui_.success_badge("NONE")
                      : ui_.warning_badge(std::to_string(report.advisory_count)));
    if (report.cves.empty()) {
        ui_.key_value("Referenced CVEs", ui_.muted("none reported by available advisories"));
        return;
    }
    ui_.key_value("Referenced CVEs", ui_.warning(visible_cves(report.cves)));
    std::cout << "\n  "
              << ui_.muted("Review the advisory and affected package before updating; "
                           "a CVE reference is not proof of local exploitability.")
              << '\n';
}
} // namespace ffc
