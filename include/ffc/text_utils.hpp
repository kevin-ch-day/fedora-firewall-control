#pragma once

#include <string>
#include <string_view>

namespace ffc {

// Normalized user- and command-provided text is kept here so parsing rules do
// not drift between interactive and non-interactive features.
[[nodiscard]] std::string trim_copy(std::string_view value);
[[nodiscard]] std::string lowercase_copy(std::string_view value);
[[nodiscard]] std::string normalize_command(std::string_view value);

} // namespace ffc
