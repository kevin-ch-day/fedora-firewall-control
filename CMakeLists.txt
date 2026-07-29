cmake_minimum_required(VERSION 3.20)
project(fedora-firewall-control VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ffc_core
    src/app/application.cpp
    src/app/command_executor.cpp
    src/app/command_line.cpp
    src/app/interactive_session.cpp
    src/core/command_runner.cpp
    src/core/secure_storage.cpp
    src/firewall/firewall_state.cpp
    src/firewall/firewalld_backend.cpp
    src/firewall/port_catalog.cpp
    src/firewall/posture_inspector.cpp
    src/firewall/port_intelligence.cpp
    src/firewall/readiness.cpp
    src/network/network_diagnostics.cpp
    src/network/network_evidence.cpp
    src/network/network_manager.cpp
    src/network/network_metadata.cpp
    src/network/vpn.cpp
    src/security/credentials.cpp
    src/security/evidence_quality.cpp
    src/security/operating_mode.cpp
    src/security/security_advisories.cpp
    src/security/security_signals.cpp
    src/security/socket_inspector.cpp
    src/security/threat_assessment.cpp
    src/ui/dashboard.cpp
    src/ui/network_renderer.cpp
    src/ui/posture_renderer.cpp
    src/ui/terminal_ui.cpp
)
target_include_directories(ffc_core PUBLIC include)
target_compile_options(ffc_core PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(fedora-firewall-control src/main.cpp)
target_link_libraries(fedora-firewall-control PRIVATE ffc_core)
add_custom_command(TARGET fedora-firewall-control POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E rm -f "$<TARGET_FILE_DIR:fedora-firewall-control>/ffc"
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    $<TARGET_FILE_NAME:fedora-firewall-control>
    "$<TARGET_FILE_DIR:fedora-firewall-control>/ffc"
  VERBATIM)

include(CTest)
if(BUILD_TESTING)
  add_executable(ffc_tests tests/test_main.cpp)
  target_link_libraries(ffc_tests PRIVATE ffc_core)
  target_compile_options(ffc_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME ffc_tests COMMAND ffc_tests)
endif()
