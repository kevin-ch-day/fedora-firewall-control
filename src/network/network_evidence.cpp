#include "ffc/network_evidence.hpp"

namespace ffc {
NetworkCapture NetworkEvidenceRecorder::capture(bool enrich, bool vpn_active) const {
    NetworkCapture capture;
    capture.metadata = metadata_.inspect(enrich);
    if (!capture.metadata.public_ip_lookup_succeeded) {
        capture.storage_result = "public-IP lookup failed";
        return capture;
    }
    capture.saved = history_.append(capture.metadata, vpn_active, capture.storage_result);
    return capture;
}

SavedNetworkHistory NetworkEvidenceRecorder::read_history() const {
    SavedNetworkHistory history;
    history.available = history_.read_recent(history.records, history.result);
    return history;
}
} // namespace ffc
