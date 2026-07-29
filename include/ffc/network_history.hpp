#pragma once

#include <string>
#include <vector>

namespace ffc {
struct NetworkMetadata;

// Owner-only persistence for locally observed public-network metadata. This
// is separate from metadata collection so history can be read without making
// a network request or constructing collection dependencies.
class NetworkHistoryStore {
public:
    [[nodiscard]] bool append(const NetworkMetadata& metadata, bool vpn_active, std::string& result) const;
    [[nodiscard]] bool read_recent(std::vector<std::string>& records, std::string& result) const;

private:
    [[nodiscard]] std::string path(std::string& error, bool create_directory) const;
};
} // namespace ffc
