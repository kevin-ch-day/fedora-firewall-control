#include "ffc/logging_engine.hpp"

#include "ffc/logging_utils.hpp"
#include "ffc/secure_storage.hpp"
#include "ffc/unique_file_descriptor.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace ffc {
namespace {
constexpr std::size_t maximum_log_bytes = 512U * 1024U;

class ScopedLogLock {
public:
    ScopedLogLock() = default;

    bool acquire(const std::string& path, std::string& error) {
        UniqueFileDescriptor descriptor{open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)};
        if (!descriptor) { error = std::strerror(errno); return false; }
        struct stat status {};
        if (fstat(descriptor.get(), &status) != 0) {
            error = std::strerror(errno);
            return false;
        }
        if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() || status.st_nlink != 1) {
            error = "log lock is not a private regular file";
            return false;
        }
        if (fchmod(descriptor.get(), S_IRUSR | S_IWUSR) != 0) {
            error = std::strerror(errno);
            return false;
        }
        while (flock(descriptor.get(), LOCK_EX) != 0) {
            if (errno == EINTR) continue;
            error = std::strerror(errno);
            return false;
        }
        descriptor_ = std::move(descriptor);
        return true;
    }

    ~ScopedLogLock() {
        if (descriptor_) flock(descriptor_.get(), LOCK_UN);
    }

    ScopedLogLock(const ScopedLogLock&) = delete;
    ScopedLogLock& operator=(const ScopedLogLock&) = delete;

private:
    UniqueFileDescriptor descriptor_;
};
}

bool LoggingEngine::record(const LogEvent& event, std::string* error) const {
    std::string storage_error;
    const auto path = secure_local_path(LocalStorageArea::State, log_file_name(event.channel), true, storage_error);
    if (path.empty()) { if (error != nullptr) *error = storage_error; return false; }
    const auto lock_path = secure_local_path(LocalStorageArea::State, log_file_name(event.channel) + ".lock", true, storage_error);
    if (lock_path.empty()) { if (error != nullptr) *error = storage_error; return false; }
    ScopedLogLock lock;
    if (!lock.acquire(lock_path, storage_error)) { if (error != nullptr) *error = storage_error; return false; }

    std::string existing;
    if (!read_private_file(path, existing, storage_error, maximum_log_bytes)) {
        // A missing log starts empty. A full log is rotated in place; unsafe
        // storage still fails closed when write_private_file validates it.
        existing = storage_error == "storage file exceeds safe size limit" ?
            format_log_event({event.channel, LogLevel::Info, "log-rotation", "retained log exceeded 512 KiB limit"}) : std::string{};
    }
    const std::string entry = format_log_event(event);
    if (existing.size() + entry.size() > maximum_log_bytes) {
        existing = format_log_event({event.channel, LogLevel::Info, "log-rotation", "retained log reached 512 KiB limit"});
    }
    if (!write_private_file(path, existing + entry, false, storage_error)) {
        if (error != nullptr) *error = storage_error;
        return false;
    }
    return true;
}
} // namespace ffc
