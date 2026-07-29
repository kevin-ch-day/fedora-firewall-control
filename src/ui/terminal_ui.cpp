#include "ffc/terminal_ui.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string_view>
#include <unistd.h>

namespace ffc {
namespace {
constexpr std::string_view hex_digits{"0123456789ABCDEF"};

void append_hex_escape(std::string& output, const unsigned char byte) {
    output += "\\x";
    output += hex_digits[byte >> 4U];
    output += hex_digits[byte & 0x0FU];
}

void append_unicode_escape(std::string& output, const unsigned int codepoint) {
    output += "\\u";
    for (int shift = 12; shift >= 0; shift -= 4)
        output += hex_digits[(codepoint >> static_cast<unsigned int>(shift)) & 0x0FU];
}

bool terminal_format_codepoint(const unsigned int codepoint) {
    return (codepoint >= 0x80U && codepoint <= 0x9FU) ||
           (codepoint >= 0x200BU && codepoint <= 0x200FU) ||
           (codepoint >= 0x202AU && codepoint <= 0x202EU) || codepoint == 0x2060U ||
           (codepoint >= 0x2066U && codepoint <= 0x2069U) || codepoint == 0xFEFFU;
}
} // namespace

std::string sanitize_terminal_text(const std::string_view text, const std::size_t maximum_bytes) {
    std::string output;
    output.reserve(std::min(text.size(), maximum_bytes));
    for (std::size_t index = 0; index < text.size();) {
        if (output.size() >= maximum_bytes) {
            output += "...[truncated]";
            break;
        }
        const auto byte = static_cast<unsigned char>(text[index]);
        // SGR only changes rendition; permit it so values deliberately styled
        // by TerminalUi retain their theme while rejecting all cursor, title,
        // clipboard, and other terminal-control sequences.
        if (byte == 0x1BU && index + 2U < text.size() && text[index + 1U] == '[') {
            std::size_t end = index + 2U;
            while (end < text.size() && ((text[end] >= '0' && text[end] <= '9') || text[end] == ';'))
                ++end;
            if (end < text.size() && text[end] == 'm') {
                output.append(text.substr(index, end - index + 1U));
                index = end + 1U;
                continue;
            }
        }
        if (byte < 0x20U || byte == 0x7FU) {
            append_hex_escape(output, byte);
            ++index;
            continue;
        }
        if (byte < 0x80U) {
            output += static_cast<char>(byte);
            ++index;
            continue;
        }
        unsigned int codepoint = 0;
        std::size_t width = 0;
        if ((byte & 0xE0U) == 0xC0U) { codepoint = byte & 0x1FU; width = 2; }
        else if ((byte & 0xF0U) == 0xE0U) { codepoint = byte & 0x0FU; width = 3; }
        else if ((byte & 0xF8U) == 0xF0U) { codepoint = byte & 0x07U; width = 4; }
        else { append_hex_escape(output, byte); ++index; continue; }
        if (index + width > text.size()) { append_hex_escape(output, byte); ++index; continue; }
        bool valid = true;
        for (std::size_t tail = 1; tail < width; ++tail) {
            const auto continuation = static_cast<unsigned char>(text[index + tail]);
            if ((continuation & 0xC0U) != 0x80U) { valid = false; break; }
            codepoint = (codepoint << 6U) | (continuation & 0x3FU);
        }
        const unsigned int minimum = width == 2 ? 0x80U : width == 3 ? 0x800U : 0x10000U;
        if (!valid || codepoint < minimum || codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            append_hex_escape(output, byte);
            ++index;
            continue;
        }
        if (terminal_format_codepoint(codepoint))
            append_unicode_escape(output, codepoint);
        else
            output.append(text.substr(index, width));
        index += width;
    }
    return output;
}

TerminalUi::TerminalUi() {
    color_ = isatty(STDOUT_FILENO) && std::getenv("NO_COLOR") == nullptr;
    const char* clear_screen = std::getenv("FFC_CLEAR_SCREEN");
    clear_screen_ = color_ && clear_screen != nullptr && std::strcmp(clear_screen, "1") == 0;
    if (const char* requested = std::getenv("FFC_THEME"); requested != nullptr) {
        const std::string name = requested;
        if (name == "defcon") theme_ = Theme::Defcon;
        else if (name == "high-contrast") theme_ = Theme::HighContrast;
    }
    if (const char* columns = std::getenv("COLUMNS"); columns != nullptr) {
        int requested = 0;
        const auto end = columns + std::strlen(columns);
        const auto [parsed_end, error] = std::from_chars(columns, end, requested);
        if (error == std::errc{} && parsed_end == end && requested >= 50)
            width_ = std::min(requested, 100);
    }
}
std::string TerminalUi::paint(const std::string& code, const std::string& text) const {
    const auto safe_text = sanitize_terminal_text(text);
    return color_ ? "\033[" + code + "m" + safe_text + "\033[0m" : safe_text;
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
void TerminalUi::clear() const {
    if (clear_screen_)
        std::cout << "\033[2J\033[H";
}
void TerminalUi::rule(char character) const { std::cout << paint(rule_code(), std::string(static_cast<size_t>(width_), character)) << '\n'; }
void TerminalUi::heading(const std::string& title, const std::string& subtitle) const {
    rule('='); std::cout << "  " << danger("///") << " " << accent(title) << " " << danger("///") << '\n'; if (!subtitle.empty()) std::cout << "  " << muted(subtitle) << '\n'; rule('=');
}
void TerminalUi::section(const std::string& title) const { std::cout << '\n' << muted("::") << " " << accent(title) << '\n'; rule('-'); }
void TerminalUi::key_value(const std::string& key, const std::string& value) const {
    constexpr std::size_t key_width = 29;
    const std::size_t padding = key.size() < key_width ? key_width - key.size() : 1;
    std::cout << "  " << muted("|") << " " << muted(key)
              << std::string(padding, ' ') << sanitize_terminal_text(value) << '\n';
}
} // namespace ffc
