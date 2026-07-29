#pragma once

#include <cstddef>
#include <string>

namespace ffc {
enum class LocalStorageArea { Config, State };

// Owner-only local storage with symlink rejection and bounded reads. This is
// used for secrets, settings, and sensitive network-history evidence.
std::string secure_local_path(LocalStorageArea area, const std::string& filename, bool create_directory, std::string& error);
bool write_private_file(const std::string& path, const std::string& content, bool append, std::string& error);
// Replaces an existing private regular file through an fsynced temporary file
// and atomic rename. The target is validated before replacement.
bool replace_private_file_atomically(const std::string& path, const std::string& content,
                                     std::string& error);
bool read_private_file(const std::string& path, std::string& content, std::string& error, std::size_t maximum_bytes = 1024U * 1024U);
} // namespace ffc
