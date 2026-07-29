#include "test_support.hpp"

#include "ffc/log_analysis.hpp"
#include "ffc/logging_engine.hpp"
#include "ffc/logging_utils.hpp"
#include "ffc/secure_storage.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>

namespace ffc::test {
void run_logging_analysis_tests() {
    const std::string sanitized = sanitize_log_value("line-one\napi=at_secret-key\x1b[31m");
    expect(sanitized.find('\n') == std::string::npos && sanitized.find("at_secret-key") == std::string::npos && sanitized.find("[REDACTED_IPIFY_KEY]") != std::string::npos && sanitized.find('\x1b') == std::string::npos, "sanitizes control characters and redacts API keys");
    char log_template[] = "/tmp/ffc-logging-state.XXXXXX";
    char* const directory = mkdtemp(log_template);
    expect(directory != nullptr, "creates isolated logging state directory");
    if (directory == nullptr) return;
    const std::optional<std::string> previous_state = std::getenv("XDG_STATE_HOME") == nullptr ? std::nullopt : std::optional<std::string>(std::getenv("XDG_STATE_HOME"));
    setenv("XDG_STATE_HOME", directory, 1);
    const LoggingEngine logger; std::string error, content;
    expect(logger.record({LogChannel::Audit, LogLevel::Info, "test-event", "key=at_test-key\n"}, &error) && logger.record({LogChannel::Security, LogLevel::Warning, "test-security-event", {}}, &error) && logger.record({LogChannel::Error, LogLevel::Error, "test-error-event", {}}, &error) && logger.record({LogChannel::Error, LogLevel::Error, "test-error-event", {}}, &error), "writes separated structured log events");
    const auto audit = secure_local_path(LocalStorageArea::State, "audit.log", false, error);
    expect(read_private_file(audit, content, error) && content.find("at_test-key") == std::string::npos && content.find("[REDACTED_IPIFY_KEY]") != std::string::npos, "stores only sanitized log values");
    const auto analysis = LocalLogAnalyzer().inspect(); bool repeated = false;
    for (const auto& event : analysis.recurring_failures) repeated = repeated || (event.channel == LogChannel::Error && event.event == "test-error-event" && event.count == 2U);
    expect(analysis.logs_available && analysis.entries >= 4U && analysis.errors == 2U && repeated, "analyzes retained logs and identifies repeated local failures");
    if (previous_state.has_value()) setenv("XDG_STATE_HOME", previous_state->c_str(), 1); else unsetenv("XDG_STATE_HOME");
    std::filesystem::remove_all(directory);
}
} // namespace ffc::test
