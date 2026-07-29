#include "test_support.hpp"

#include "ffc/secure_storage.hpp"
#include "ffc/network_history.hpp"
#include "ffc/network_metadata.hpp"
#include "ffc/operating_mode.hpp"

#include <cstdlib>
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
    expect(write_private_file(file, "original", false, error) &&
               replace_private_file_atomically(file, "replacement", error) &&
               read_private_file(file, content, error) && content == "replacement" &&
               link(file.c_str(), hard_link.c_str()) == 0,
           "atomically replaces private storage before creating a hard-link fixture");
    error.clear();
    expect(!write_private_file(file, "unsafe replacement", false, error) &&
               error.find("hard links") != std::string::npos,
           "rejects hard-linked storage before truncation");
    expect(unlink(hard_link.c_str()) == 0, "removes hard-link fixture");
    error.clear();
    expect(read_private_file(file, content, error) && content == "replacement",
           "preserves content after refused unsafe overwrite");
    error.clear();
    expect(!replace_private_file_atomically("/unsafe-ffc-test", "no", error) &&
               error.find("unsafe") != std::string::npos,
           "refuses atomic replacement directly under the filesystem root");
    expect(secure_local_path(LocalStorageArea::Config, "../escape", false, error).empty() && secure_local_path(LocalStorageArea::State, std::string("embedded\0name", 13), false, error).empty(), "rejects unsafe storage filenames");
    std::filesystem::remove_all(directory);

    char mode_template[] = "/tmp/ffc-mode-test.XXXXXX";
    char* const mode_directory = mkdtemp(mode_template);
    expect(mode_directory != nullptr, "creates isolated operating-mode storage");
    if (mode_directory == nullptr) return;
    const char* previous_xdg_config = std::getenv("XDG_CONFIG_HOME");
    const std::string saved_xdg_config = previous_xdg_config == nullptr ? "" : previous_xdg_config;
    const bool had_xdg_config = previous_xdg_config != nullptr;
    setenv("XDG_CONFIG_HOME", mode_directory, 1);
    OperatingModeStore modes;
    const auto default_mode = modes.load();
    std::string mode_result;
    expect(default_mode.mode == OperatingMode::Normal &&
               default_mode.status == OperatingModeLoadStatus::Defaulted &&
               modes.save(OperatingMode::HostileNetwork, mode_result),
           "uses an explicit normal default only when operating-mode storage is absent");
    const auto saved_mode = modes.load();
    std::string mode_path_error;
    const auto mode_path = secure_local_path(LocalStorageArea::Config, "mode", false, mode_path_error);
    std::string corrupt_error;
    expect(saved_mode.mode == OperatingMode::HostileNetwork &&
               saved_mode.status == OperatingModeLoadStatus::Available &&
               write_private_file(mode_path, "hostile-corrupt", false, corrupt_error),
           "loads a valid persisted hostile operating mode before exercising corruption handling");
    const auto corrupt_mode = modes.load();
    expect(corrupt_mode.mode == OperatingMode::HostileNetwork &&
               corrupt_mode.status == OperatingModeLoadStatus::Invalid &&
               !corrupt_mode.diagnostic.empty(),
           "fails closed to hostile criteria when existing operating-mode storage is invalid");
    if (had_xdg_config) setenv("XDG_CONFIG_HOME", saved_xdg_config.c_str(), 1);
    else unsetenv("XDG_CONFIG_HOME");
    std::filesystem::remove_all(mode_directory);

    char history_template[] = "/tmp/ffc-history-test.XXXXXX";
    char* const history_directory = mkdtemp(history_template);
    expect(history_directory != nullptr, "creates isolated network-history storage");
    if (history_directory == nullptr) return;
    const char* previous_xdg_state = std::getenv("XDG_STATE_HOME");
    const std::string saved_xdg_state = previous_xdg_state == nullptr ? "" : previous_xdg_state;
    const bool had_xdg_state = previous_xdg_state != nullptr;
    setenv("XDG_STATE_HOME", history_directory, 1);
    NetworkHistoryStore history;
    NetworkMetadata metadata;
    metadata.public_ip = "198.51.100.42";
    std::string history_result;
    bool history_written = true;
    for (unsigned int index = 0; index <= 512U; ++index) {
        metadata.observed_at_utc = std::to_string(index);
        history_written = history_written && history.append(metadata, false, history_result);
    }
    std::vector<std::string> history_records;
    expect(history_written && history.read_recent(history_records, history_result) &&
               history_records.size() == 512U && history_records.front().starts_with("1\t") &&
               history_records.back().starts_with("512\t"),
           "compacts network history to its newest bounded record window");
    if (had_xdg_state) setenv("XDG_STATE_HOME", saved_xdg_state.c_str(), 1);
    else unsetenv("XDG_STATE_HOME");
    std::filesystem::remove_all(history_directory);
}
} // namespace ffc::test
