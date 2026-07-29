#include "test_support.hpp"

#include "ffc/security_advisories.hpp"

#include <vector>

namespace ffc::test {
void run_security_advisory_tests() {
    StubCommandRunner runner({0, R"([{"advisory_name":"FEDORA-test","references":[{"reference_id":"CVE-2026-1234"},{"reference_id":"CVE-2026-1234"},{"reference_id":"CVE-2025-9999"}]}])", {}});
    const auto report = SecurityAdvisoryInspector(runner).inspect();
    expect(report.query_succeeded && report.advisory_count == 1 && report.cves == std::vector<std::string>{"CVE-2025-9999", "CVE-2026-1234"}, "summarizes available CVE advisories deterministically");
}
} // namespace ffc::test
