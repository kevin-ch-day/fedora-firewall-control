#include "ffc/text_utils.hpp"

#include <algorithm>
#include <cctype>
#include <ranges>

namespace ffc {
namespace {
bool is_space(const unsigned char character) {
    return std::isspace(character) != 0;
}
}

std::string trim_copy(const std::string_view value) {
    const auto first = std::ranges::find_if_not(value, is_space);
    if (first == value.end()) return {};

    const auto last = std::ranges::find_if_not(value.rbegin(), value.rend(), is_space).base();
    return {first, last};
}

std::string lowercase_copy(const std::string_view value) {
    std::string result(value.size(), '\0');
    std::ranges::transform(value, result.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::string normalize_command(const std::string_view value) {
    return lowercase_copy(trim_copy(value));
}

} // namespace ffc
