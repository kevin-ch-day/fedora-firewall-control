#include "test_suites.hpp"
#include "test_support.hpp"

int main() {
    ffc::test::run_firewall_parsing_tests();
    ffc::test::run_network_path_tests();
    ffc::test::run_diagnostics_tests();
    ffc::test::run_command_executor_tests();
    ffc::test::run_port_command_tests();
    ffc::test::run_storage_tests();
    ffc::test::run_logging_analysis_tests();
    ffc::test::run_process_runner_tests();
    ffc::test::run_security_advisory_tests();
    ffc::test::run_posture_threat_tests();
    ffc::test::run_text_utils_tests();
    ffc::test::run_unique_file_descriptor_tests();
    return ffc::test::failures == 0 ? 0 : 1;
}
