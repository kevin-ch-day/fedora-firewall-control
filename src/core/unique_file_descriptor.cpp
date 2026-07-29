#include "ffc/unique_file_descriptor.hpp"

#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <utility>

namespace ffc {
UniqueFileDescriptor::UniqueFileDescriptor(const int descriptor) noexcept : descriptor_(descriptor) {}

UniqueFileDescriptor::~UniqueFileDescriptor() {
    if (valid()) ::close(descriptor_);
}

UniqueFileDescriptor::UniqueFileDescriptor(UniqueFileDescriptor&& other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)) {}

UniqueFileDescriptor& UniqueFileDescriptor::operator=(UniqueFileDescriptor&& other) noexcept {
    if (this == &other) return *this;
    if (valid()) ::close(descriptor_);
    descriptor_ = std::exchange(other.descriptor_, -1);
    return *this;
}

int UniqueFileDescriptor::get() const noexcept { return descriptor_; }
bool UniqueFileDescriptor::valid() const noexcept { return descriptor_ >= 0; }
UniqueFileDescriptor::operator bool() const noexcept { return valid(); }

bool UniqueFileDescriptor::close(std::string& error) noexcept {
    if (!valid()) return true;
    const int descriptor = std::exchange(descriptor_, -1);
    if (::close(descriptor) == 0) return true;
    error = std::strerror(errno);
    return false;
}
} // namespace ffc
