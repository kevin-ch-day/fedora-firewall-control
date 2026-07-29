cmake_minimum_required(VERSION 3.20)

project(fedora-firewall-control
  VERSION 0.1.1
  DESCRIPTION "Read-only Fedora firewalld posture console"
  LANGUAGES CXX
)

include(CTest)
include(GNUInstallDirs)

option(FFC_USE_CCACHE "Use ccache when it is available" ON)
option(FFC_WARNINGS_AS_ERRORS "Treat project compiler warnings as errors" ON)
option(FFC_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(FFC_ENABLE_COVERAGE "Enable compiler coverage instrumentation" OFF)
option(FFC_EXPORT_COMPILE_COMMANDS "Write compile_commands.json for editors and analysis tools" ON)

if(FFC_EXPORT_COMPILE_COMMANDS)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

if(FFC_USE_CCACHE)
  find_program(FFC_CCACHE_PROGRAM ccache)
  if(FFC_CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${FFC_CCACHE_PROGRAM}")
    message(STATUS "Using ccache for C++ compilation")
  else()
    message(STATUS "ccache not found; building without a compiler cache")
  endif()
endif()

add_library(ffc_project_warnings INTERFACE)
target_compile_options(ffc_project_warnings INTERFACE
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>
)
if(FFC_WARNINGS_AS_ERRORS)
  target_compile_options(ffc_project_warnings INTERFACE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Werror>
  )
endif()

add_library(ffc_project_instrumentation INTERFACE)
if(FFC_ENABLE_SANITIZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    message(FATAL_ERROR "FFC_ENABLE_SANITIZERS requires GCC, Clang, or AppleClang")
  endif()
  target_compile_options(ffc_project_instrumentation INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(ffc_project_instrumentation INTERFACE -fsanitize=address,undefined)
endif()
if(FFC_ENABLE_COVERAGE)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    message(FATAL_ERROR "FFC_ENABLE_COVERAGE requires GCC, Clang, or AppleClang")
  endif()
  target_compile_options(ffc_project_instrumentation INTERFACE --coverage)
  target_link_options(ffc_project_instrumentation INTERFACE --coverage)
endif()

set(FFC_CORE_SOURCES
  src/app/application.cpp
  src/app/command_executor.cpp
  src/app/command_line.cpp
  src/app/interactive_session.cpp
  src/core/command_runner.cpp
  src/core/secure_storage.cpp
  src/core/text_utils.cpp
  src/core/unique_file_descriptor.cpp
  src/firewall/firewall_state.cpp
  src/firewall/firewalld_backend.cpp
  src/firewall/port_catalog.cpp
  src/firewall/port_intelligence.cpp
  src/firewall/posture_inspector.cpp
  src/firewall/readiness.cpp
  src/logging/analysis/log_analysis.cpp
  src/logging/core/logging_core.cpp
  src/logging/engine/logging_engine.cpp
  src/logging/utils/logging_utils.cpp
  src/network/network_address.cpp
  src/network/network_diagnostics.cpp
  src/network/network_evidence.cpp
  src/network/network_history.cpp
  src/network/network_manager.cpp
  src/network/network_metadata.cpp
  src/network/network_path_parser.cpp
  src/network/vpn.cpp
  src/security/credentials.cpp
  src/security/evidence_quality.cpp
  src/security/operating_mode.cpp
  src/security/security_advisories.cpp
  src/security/security_signals.cpp
  src/security/socket_inspector.cpp
  src/security/threat_assessment.cpp
  src/ui/dashboard.cpp
  src/ui/log_renderer.cpp
  src/ui/network_diagnostics_renderer.cpp
  src/ui/network_renderer.cpp
  src/ui/posture_renderer.cpp
  src/ui/security_advisory_renderer.cpp
  src/ui/terminal_ui.cpp
)

add_library(ffc_core ${FFC_CORE_SOURCES})
target_compile_features(ffc_core PUBLIC cxx_std_20)
target_include_directories(ffc_core PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ffc_core PRIVATE ffc_project_warnings PUBLIC ffc_project_instrumentation)

add_executable(fedora-firewall-control src/main.cpp)
target_link_libraries(fedora-firewall-control PRIVATE ffc_core ffc_project_warnings)

add_custom_command(TARGET fedora-firewall-control POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E rm -f "$<TARGET_FILE_DIR:fedora-firewall-control>/ffc"
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    $<TARGET_FILE_NAME:fedora-firewall-control>
    "$<TARGET_FILE_DIR:fedora-firewall-control>/ffc"
  VERBATIM
)

install(TARGETS fedora-firewall-control RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTING)
  set(FFC_TEST_SOURCES
    tests/test_main.cpp
    tests/test_diagnostics.cpp
    tests/test_command_executor.cpp
    tests/test_firewall_parsing.cpp
    tests/test_logging_analysis.cpp
    tests/test_network_paths.cpp
    tests/test_port_command.cpp
    tests/test_posture_threat.cpp
    tests/test_process_runner.cpp
    tests/test_security_advisories.cpp
    tests/test_storage.cpp
    tests/test_text_utils.cpp
    tests/test_unique_file_descriptor.cpp
  )
  add_executable(ffc_tests ${FFC_TEST_SOURCES})
  target_link_libraries(ffc_tests PRIVATE ffc_core ffc_project_warnings)
  add_test(NAME ffc_tests COMMAND ffc_tests)
endif()

message(STATUS "fedora-firewall-control ${PROJECT_VERSION}: ${CMAKE_BUILD_TYPE} build")
