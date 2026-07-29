#include "ffc/security_advisories.hpp"

#include <algorithm>
#include <regex>

namespace ffc {
namespace {
std::size_t occurrences(const std::string& text, const std::string& needle) {
    std::size_t count = 0;
    for (std::size_t position = text.find(needle); position != std::string::npos; position = text.find(needle, position + needle.size())) ++count;
    return count;
}
} // namespace

SecurityAdvisoryReport SecurityAdvisoryInspector::inspect() const {
    const auto result = runner_.run({"dnf5", "advisory", "list", "--security", "--with-cve", "--contains-pkgs=firewalld,NetworkManager,nftables,kernel,kernel-core,openssl,curl,dbus,polkit", "--json"});
    SecurityAdvisoryReport report;
    report.dnf_available = result.exit_code != 127;
    report.query_succeeded = result.success();
    if (!report.dnf_available) { report.diagnostic = "dnf5 is not installed"; return report; }
    if (!report.query_succeeded) { report.diagnostic = result.stderr_text.empty() ? "DNF5 advisory query failed" : result.stderr_text; return report; }

    report.advisory_count = occurrences(result.stdout_text, "\"advisory_name\"");
    const std::regex cve_pattern(R"(CVE-[0-9]{4}-[0-9]{4,})");
    for (std::sregex_iterator match(result.stdout_text.begin(), result.stdout_text.end(), cve_pattern), end; match != end; ++match) report.cves.push_back(match->str());
    std::sort(report.cves.begin(), report.cves.end());
    report.cves.erase(std::unique(report.cves.begin(), report.cves.end()), report.cves.end());
    return report;
}
} // namespace ffc
