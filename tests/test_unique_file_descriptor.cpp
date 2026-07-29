#include "test_support.hpp"

#include "ffc/unique_file_descriptor.hpp"

#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <utility>

namespace ffc::test {
void run_unique_file_descriptor_tests() {
    UniqueFileDescriptor descriptor{open("/dev/null", O_RDONLY | O_CLOEXEC)};
    expect(descriptor.valid(), "owns a successfully opened descriptor");

    const int original_descriptor = descriptor.get();
    UniqueFileDescriptor moved{std::move(descriptor)};
    expect(moved && moved.get() == original_descriptor,
           "transfers descriptor ownership exactly once");

    std::string error;
    expect(moved.close(error) && !moved, "closes an owned descriptor explicitly and clears ownership");
}
} // namespace ffc::test
