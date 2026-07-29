#include "test_support.hpp"

#include "ffc/secure_storage.hpp"

#include <filesystem>
#include <string>
#include <unistd.h>

namespace ffc::test {
void run_storage_tests() {
    char storage_template[] = "/tmp/ffc-storage-test.XXXXXX";
    char* const directory = mkdtemp(storage_template);
    expect(directory != nullptr, "creates isolated storage test directory");
    if (directory == nullptr) return;
    const std::string file = std::string(directory) + "/private-data";
    const std::string hard_link = std::string(directory) + "/private-data-link";
    std::string error, content;
    expect(write_private_file(file, "original", false, error) && link(file.c_str(), hard_link.c_str()) == 0, "creates private storage and hard-link fixture");
    error.clear();
    expect(!write_private_file(file, "replacement", false, error) && error.find("hard links") != std::string::npos, "rejects hard-linked storage before truncation");
    expect(unlink(hard_link.c_str()) == 0, "removes hard-link fixture");
    error.clear();
    expect(read_private_file(file, content, error) && content == "original", "preserves content after refused unsafe overwrite");
    expect(secure_local_path(LocalStorageArea::Config, "../escape", false, error).empty() && secure_local_path(LocalStorageArea::State, std::string("embedded\0name", 13), false, error).empty(), "rejects unsafe storage filenames");
    std::filesystem::remove_all(directory);
}
} // namespace ffc::test
