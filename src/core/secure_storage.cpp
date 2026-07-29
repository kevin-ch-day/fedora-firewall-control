#include "ffc/secure_storage.hpp"
#include "ffc/unique_file_descriptor.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ffc {
namespace {
bool safe_filename(const std::string& filename) {
    return !filename.empty() && filename != "." && filename != ".." &&
           filename.find_first_of("/\\\\") == std::string::npos &&
           filename.find('\0') == std::string::npos;
}

bool private_directory(const std::filesystem::path& directory, std::string& error) {
    struct stat status {};
    if (lstat(directory.c_str(), &status) != 0) { error = std::strerror(errno); return false; }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) { error = "storage path is not a directory"; return false; }
    if (status.st_uid != geteuid()) { error = "storage directory is not owned by the current user"; return false; }
    if (chmod(directory.c_str(), S_IRWXU) != 0) { error = std::strerror(errno); return false; }
    return true;
}
bool private_regular_file(int descriptor, std::string& error) {
    struct stat status {};
    if (fstat(descriptor, &status) != 0) { error = std::strerror(errno); return false; }
    if (!S_ISREG(status.st_mode)) { error = "storage path is not a regular file"; return false; }
    if (status.st_uid != geteuid()) { error = "storage file is not owned by the current user"; return false; }
    if (status.st_nlink != 1) { error = "storage file must not have hard links"; return false; }
    return true;
}

bool write_all(const int descriptor, const std::string& content, std::string& error) {
    const char* remaining = content.data();
    std::size_t bytes = content.size();
    while (bytes > 0) {
        const ssize_t written = write(descriptor, remaining, bytes);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            error = written == 0 ? "storage write made no progress" : std::strerror(errno);
            return false;
        }
        remaining += written;
        bytes -= static_cast<std::size_t>(written);
    }
    return true;
}
} // namespace

std::string secure_local_path(LocalStorageArea area, const std::string& filename, bool create_directory, std::string& error) {
    if (!safe_filename(filename)) { error = "storage filename is unsafe"; return {}; }
    const char* xdg = std::getenv(area == LocalStorageArea::Config ? "XDG_CONFIG_HOME" : "XDG_STATE_HOME");
    const char* home = std::getenv("HOME");
    std::filesystem::path directory;
    if (xdg != nullptr && *xdg != '\0') directory = xdg;
    else if (home != nullptr && *home != '\0') directory = std::filesystem::path(home) / (area == LocalStorageArea::Config ? ".config" : ".local/state");
    else { error = "HOME and XDG storage variables are unavailable"; return {}; }
    directory /= "fedora-firewall-control";
    if (create_directory) {
        std::error_code code; std::filesystem::create_directories(directory, code);
        if (code) { error = code.message(); return {}; }
    }
    if (std::filesystem::exists(directory) && !private_directory(directory, error)) return {};
    return (directory / filename).string();
}

bool write_private_file(const std::string& path, const std::string& content, bool append, std::string& error) {
    // Do not truncate before checking ownership and file type. Otherwise a
    // caller could lose data if a path was replaced between lookups.
    const int flags = O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | (append ? O_APPEND : 0);
    UniqueFileDescriptor descriptor{open(path.c_str(), flags, S_IRUSR | S_IWUSR)};
    if (!descriptor) { error = std::strerror(errno); return false; }
    bool success = private_regular_file(descriptor.get(), error) && fchmod(descriptor.get(), S_IRUSR | S_IWUSR) == 0;
    if (!success && error.empty()) error = std::strerror(errno);
    if (success && !append && (ftruncate(descriptor.get(), 0) != 0 || lseek(descriptor.get(), 0, SEEK_SET) < 0)) {
        success = false; error = std::strerror(errno);
    }
    if (success && !write_all(descriptor.get(), content, error)) success = false;
    if (success && fsync(descriptor.get()) != 0) { success = false; error = std::strerror(errno); }
    if (success && !descriptor.close(error)) success = false;
    return success;
}

bool replace_private_file_atomically(const std::string& path, const std::string& content,
                                     std::string& error) {
    const auto separator = path.find_last_of('/');
    if (separator == std::string::npos || separator + 1U == path.size()) {
        error = "storage replacement path is invalid";
        return false;
    }
    const std::string directory = separator == 0U ? "/" : path.substr(0, separator);
    const std::string filename = path.substr(separator + 1U);
    if (directory == "/" || !safe_filename(filename) || !private_directory(directory, error)) {
        if (error.empty()) error = "storage replacement directory is unsafe";
        return false;
    }

    UniqueFileDescriptor directory_descriptor{
        open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (!directory_descriptor) {
        error = std::strerror(errno);
        return false;
    }
    struct stat existing {};
    if (fstatat(directory_descriptor.get(), filename.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(existing.st_mode) || S_ISLNK(existing.st_mode) ||
            existing.st_uid != geteuid() || existing.st_nlink != 1) {
            error = "storage file is not a private regular file";
            return false;
        }
    } else if (errno != ENOENT) {
        error = std::strerror(errno);
        return false;
    }

    std::string temporary;
    UniqueFileDescriptor temporary_descriptor;
    for (unsigned int attempt = 0; attempt < 128U; ++attempt) {
        temporary = "." + filename + ".tmp." + std::to_string(getpid()) + "." +
                    std::to_string(attempt);
        temporary_descriptor = UniqueFileDescriptor{openat(
            directory_descriptor.get(), temporary.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)};
        if (temporary_descriptor) break;
        if (errno != EEXIST) {
            error = std::strerror(errno);
            return false;
        }
    }
    if (!temporary_descriptor) {
        error = "could not allocate private replacement file";
        return false;
    }
    bool success = private_regular_file(temporary_descriptor.get(), error) &&
                   fchmod(temporary_descriptor.get(), S_IRUSR | S_IWUSR) == 0;
    if (!success && error.empty()) error = std::strerror(errno);
    if (success && !write_all(temporary_descriptor.get(), content, error)) success = false;
    if (success && fsync(temporary_descriptor.get()) != 0) {
        error = std::strerror(errno);
        success = false;
    }
    if (success && !temporary_descriptor.close(error)) success = false;
    if (success && renameat(directory_descriptor.get(), temporary.c_str(), directory_descriptor.get(),
                            filename.c_str()) != 0) {
        error = std::strerror(errno);
        success = false;
    }
    if (success && fsync(directory_descriptor.get()) != 0) {
        error = std::strerror(errno);
        success = false;
    }
    if (!success && temporary_descriptor)
        (void)temporary_descriptor.close(error);
    if (!success)
        unlinkat(directory_descriptor.get(), temporary.c_str(), 0);
    return success;
}

bool read_private_file(const std::string& path, std::string& content, std::string& error, std::size_t maximum_bytes) {
    UniqueFileDescriptor descriptor{open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (!descriptor) { error = std::strerror(errno); return false; }
    if (!private_regular_file(descriptor.get(), error)) return false;
    content.clear(); char buffer[4096];
    while (true) {
        const ssize_t count = read(descriptor.get(), buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { error = std::strerror(errno); return false; }
        if (count == 0) break;
        if (content.size() + static_cast<std::size_t>(count) > maximum_bytes) { error = "storage file exceeds safe size limit"; return false; }
        content.append(buffer, static_cast<std::size_t>(count));
    }
    return descriptor.close(error);
}
} // namespace ffc
