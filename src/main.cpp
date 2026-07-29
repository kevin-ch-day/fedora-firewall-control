#include "ffc/application.hpp"
#include "ffc/command_runner.hpp"
#include "ffc/firewalld_backend.hpp"
#include "ffc/terminal_ui.hpp"

int main(int argc, char** argv) {
    ffc::ProcessCommandRunner runner;
    ffc::FirewalldCommandBackend backend(runner);
    ffc::TerminalUi ui;
    ffc::Dashboard dashboard(ui);
    return ffc::Application(backend, dashboard).run(argc, argv);
}
