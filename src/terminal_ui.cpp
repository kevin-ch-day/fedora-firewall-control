#include "ffc/terminal_ui.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <unistd.h>

namespace ffc {
TerminalUi::TerminalUi() {
    color_ = isatty(STDOUT_FILENO) && std::getenv("NO_COLOR") == nullptr;
    if (const char* columns = std::getenv("COLUMNS"); columns != nullptr) {
        const int requested = std::atoi(columns);
        if (requested >= 50) width_ = std::min(requested, 100);
    }
}
std::string TerminalUi::paint(const std::string& code, const std::string& text) const {
    return color_ ? "\033[" + code + "m" + text + "\033[0m" : text;
}
std::string TerminalUi::accent(const std::string& text) const { return paint("1;36", text); }
std::string TerminalUi::success(const std::string& text) const { return paint("1;32", text); }
std::string TerminalUi::warning(const std::string& text) const { return paint("1;33", text); }
std::string TerminalUi::danger(const std::string& text) const { return paint("1;31", text); }
std::string TerminalUi::muted(const std::string& text) const { return paint("2;37", text); }
std::string TerminalUi::badge(const std::string& text, const std::string& color) const { return paint("1;" + color, "[ " + text + " ]"); }
void TerminalUi::clear() const { if (color_) std::cout << "\033[2J\033[H"; }
void TerminalUi::rule(char character) const { std::cout << std::string(static_cast<size_t>(width_), character) << '\n'; }
void TerminalUi::heading(const std::string& title, const std::string& subtitle) const {
    rule('='); std::cout << accent(title) << '\n'; if (!subtitle.empty()) std::cout << muted(subtitle) << '\n'; rule('=');
}
void TerminalUi::section(const std::string& title) const { std::cout << '\n' << accent(title) << '\n'; rule(); }
void TerminalUi::key_value(const std::string& key, const std::string& value) const { std::cout << "  " << muted(key + ":") << " " << value << '\n'; }
} // namespace ffc
