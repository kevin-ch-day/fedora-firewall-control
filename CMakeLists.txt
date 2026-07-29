cmake_minimum_required(VERSION 3.20)
project(fedora-firewall-control VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ffc_core
    src/application.cpp
    src/command_runner.cpp
    src/dashboard.cpp
    src/firewall_state.cpp
    src/firewalld_backend.cpp
    src/readiness.cpp
    src/terminal_ui.cpp
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
