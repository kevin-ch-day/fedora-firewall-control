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
    [[nodiscard]] std::string badge(const std::string& text, const std::string& color) const;
    void clear() const;
    void rule(char character = '-') const;
    void heading(const std::string& title, const std::string& subtitle = {}) const;
    void section(const std::string& title) const;
    void key_value(const std::string& key, const std::string& value) const;
private:
    bool color_{false};
    int width_{72};
    [[nodiscard]] std::string paint(const std::string& code, const std::string& text) const;
};
} // namespace ffc
