#include "ffc/terminal_ui.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <unistd.h>

namespace ffc {
TerminalUi::TerminalUi() {
    color_ = isatty(STDOUT_FILENO) && std::getenv("NO_COLOR") == nullptr;
    if (const char* requested = std::getenv("FFC_THEME"); requested != nullptr) {
        const std::string name = requested;
        if (name == "defcon") theme_ = Theme::Defcon;
        else if (name == "high-contrast") theme_ = Theme::HighContrast;
    }
    if (const char* columns = std::getenv("COLUMNS"); columns != nullptr) {
        const int requested = std::atoi(columns);
        if (requested >= 50) width_ = std::min(requested, 100);
    }
}
std::string TerminalUi::paint(const std::string& code, const std::string& text) const {
    return color_ ? "\033[" + code + "m" + text + "\033[0m" : text;
}
std::string TerminalUi::accent_code() const {
    if (theme_ == Theme::Defcon) return "1;36";
    if (theme_ == Theme::HighContrast) return "1;97;44";
    return "1;97";
}
std::string TerminalUi::rule_code() const {
    if (theme_ == Theme::Defcon) return "2;36";
    if (theme_ == Theme::HighContrast) return "1;97";
    return "2;31";
}
std::string TerminalUi::accent(const std::string& text) const { return paint(accent_code(), text); }
std::string TerminalUi::success(const std::string& text) const { return paint("1;32", text); }
std::string TerminalUi::warning(const std::string& text) const { return paint("1;33", text); }
std::string TerminalUi::danger(const std::string& text) const { return paint(theme_ == Theme::Industrial ? "1;97;41" : "1;31", text); }
std::string TerminalUi::muted(const std::string& text) const { return paint("2;37", text); }
std::string TerminalUi::badge(const std::string& text, const std::string& code) const { return paint(code, "[ " + text + " ]"); }
std::string TerminalUi::success_badge(const std::string& text) const { return badge(text, "1;32"); }
std::string TerminalUi::warning_badge(const std::string& text) const { return badge(text, "1;33"); }
std::string TerminalUi::danger_badge(const std::string& text) const { return badge(text, theme_ == Theme::Industrial ? "1;97;41" : "1;31"); }
std::string TerminalUi::neutral_badge(const std::string& text) const { return badge(text, accent_code()); }
std::string TerminalUi::keycap(const std::string& text) const { return badge(text, accent_code()); }
std::string TerminalUi::theme_name() const {
    if (theme_ == Theme::Defcon) return "defcon";
    if (theme_ == Theme::HighContrast) return "high-contrast";
    return "industrial";
}
void TerminalUi::clear() const { if (color_) std::cout << "\033[2J\033[H"; }
void TerminalUi::rule(char character) const { std::cout << paint(rule_code(), std::string(static_cast<size_t>(width_), character)) << '\n'; }
void TerminalUi::heading(const std::string& title, const std::string& subtitle) const {
    rule('='); std::cout << "  " << danger("///") << " " << accent(title) << " " << danger("///") << '\n'; if (!subtitle.empty()) std::cout << "  " << muted(subtitle) << '\n'; rule('=');
}
void TerminalUi::section(const std::string& title) const { std::cout << '\n' << muted("::") << " " << accent(title) << '\n'; rule('-'); }
void TerminalUi::key_value(const std::string& key, const std::string& value) const {
    constexpr std::size_t key_width = 29;
    const std::size_t padding = key.size() < key_width ? key_width - key.size() : 1;
    std::cout << "  " << muted("|") << " " << muted(key) << std::string(padding, ' ') << value << '\n';
}
} // namespace ffc
