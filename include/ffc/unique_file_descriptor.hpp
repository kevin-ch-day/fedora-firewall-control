#pragma once

#include <string>

namespace ffc {

// Move-only POSIX descriptor owner. It closes automatically on every return
// path; close(error) is available when a caller must surface a close failure.
class UniqueFileDescriptor final {
public:
    explicit UniqueFileDescriptor(int descriptor = -1) noexcept;
    ~UniqueFileDescriptor();

    UniqueFileDescriptor(const UniqueFileDescriptor&) = delete;
    UniqueFileDescriptor& operator=(const UniqueFileDescriptor&) = delete;
    UniqueFileDescriptor(UniqueFileDescriptor&& other) noexcept;
    UniqueFileDescriptor& operator=(UniqueFileDescriptor&& other) noexcept;

    [[nodiscard]] int get() const noexcept;
    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept;
    [[nodiscard]] bool close(std::string& error) noexcept;

private:
    int descriptor_{-1};
};

} // namespace ffc
