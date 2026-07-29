#pragma once

#include "ffc/network_metadata.hpp"

namespace ffc {
struct NetworkCapture {
    NetworkMetadata metadata;
    bool saved{false};
    std::string storage_result;

    [[nodiscard]] bool successful() const { return metadata.public_ip_lookup_succeeded && saved; }
    [[nodiscard]] std::string history_status() const { return saved ? storage_result : "not saved: " + storage_result; }
};

struct SavedNetworkHistory {
    std::vector<std::string> records;
    bool available{false};
    std::string result;

    [[nodiscard]] std::string display_status() const { return available ? result : "history unavailable: " + result; }
};

// Owns the explicit network-evidence workflow: collect, conditionally persist,
// and read history. It intentionally does not run during posture refreshes.
class NetworkEvidenceService {
public:
    NetworkEvidenceService(const NetworkMetadataInspector& metadata, const NetworkHistoryStore& history) : metadata_(metadata), history_(history) {}

    [[nodiscard]] NetworkCapture capture(bool enrich, bool vpn_active) const;
    [[nodiscard]] SavedNetworkHistory read_history() const;

private:
    const NetworkMetadataInspector& metadata_;
    const NetworkHistoryStore& history_;
};
} // namespace ffc
