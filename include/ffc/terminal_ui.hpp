#pragma once

#include <string>

namespace ffc {
class TerminalUi {
public:
    TerminalUi();
    [[nodiscard]] std::string accent(const std::string& text) const;
    [[nodiscard]] std::string success(const std::string& text) const;
    [[nodiscard]] std::string warning(const std::string& text) const;
    [[nodiscard]] std::string danger(const std::string& text) const;
    [[nodiscard]] std::string muted(const std::string& text) const;
    [[nodiscard]] std::string success_badge(const std::string& text) const;
    [[nodiscard]] std::string warning_badge(const std::string& text) const;
    [[nodiscard]] std::string danger_badge(const std::string& text) const;
    [[nodiscard]] std::string neutral_badge(const std::string& text) const;
    [[nodiscard]] std::string keycap(const std::string& text) const;
    [[nodiscard]] std::string theme_name() const;
    void clear() const;
    void rule(char character = '-') const;
    void heading(const std::string& title, const std::string& subtitle = {}) const;
    void section(const std::string& title) const;
    void key_value(const std::string& key, const std::string& value) const;
private:
    enum class Theme { Industrial, Defcon, HighContrast };
    bool color_{false};
    int width_{72};
    Theme theme_{Theme::Industrial};
    [[nodiscard]] std::string paint(const std::string& code, const std::string& text) const;
    [[nodiscard]] std::string accent_code() const;
    [[nodiscard]] std::string rule_code() const;
    [[nodiscard]] std::string badge(const std::string& text, const std::string& code) const;
};
} // namespace ffc
