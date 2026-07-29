#include "port_catalog.hpp"

#include <array>

namespace ffc::port_catalog {
namespace {
struct ServiceEntry {
    std::string_view protocol;
    unsigned short port{0};
    std::string_view label;
};

struct ServiceRangeEntry {
    std::string_view protocol;
    unsigned short first_port{0};
    unsigned short last_port{0};
    std::string_view label;
};

// These are common operational ports not covered by Fedora's minimal
// /etc/services file. Keep labels descriptive rather than asserting a process.
constexpr std::array services{
    ServiceEntry{"tcp", 1755, "Microsoft Media Server"},
    ServiceEntry{"tcp", 3129, "HTTP proxy"},
    ServiceEntry{"tcp", 4040, "Apache Spark web UI"},
    ServiceEntry{"tcp", 4317, "OpenTelemetry gRPC collector"},
    ServiceEntry{"tcp", 4318, "OpenTelemetry HTTP collector"},
    ServiceEntry{"tcp", 4443, "alternate HTTPS"},
    ServiceEntry{"tcp", 5044, "Logstash Beats input"},
    ServiceEntry{"tcp", 5141, "Syslog over TLS (alternate)"},
    ServiceEntry{"tcp", 6514, "Syslog over TLS"},
    ServiceEntry{"tcp", 7946, "Docker Swarm control"},
    ServiceEntry{"tcp", 8126, "Datadog trace intake"},
    ServiceEntry{"tcp", 8337, "Bitcoin JSON-RPC"},
    ServiceEntry{"tcp", 8883, "MQTT over TLS"},
    ServiceEntry{"tcp", 9001, "Tor relay ORPort (common)"},
    ServiceEntry{"tcp", 9091, "Prometheus Pushgateway"},
    ServiceEntry{"tcp", 9094, "Kafka"},
    ServiceEntry{"tcp", 9187, "PostgreSQL exporter"},
    ServiceEntry{"tcp", 9443, "alternate HTTPS"},
    ServiceEntry{"tcp", 10248, "Kubernetes kube-proxy health server"},
    ServiceEntry{"tcp", 10249, "Kubernetes kube-proxy metrics"},
    ServiceEntry{"tcp", 10254, "Kubernetes ingress controller metrics"},
    ServiceEntry{"tcp", 10256, "Kubernetes kube-proxy health server"},
    ServiceEntry{"tcp", 12201, "Graylog GELF input"},
    ServiceEntry{"tcp", 1514, "syslog/agent event intake"},
    ServiceEntry{"tcp", 1515, "Wazuh agent enrollment"},
    ServiceEntry{"tcp", 16443, "MicroK8s Kubernetes API"},
    ServiceEntry{"tcp", 19999, "Netdata dashboard"},
    ServiceEntry{"tcp", 2003, "Graphite plaintext metrics"},
    ServiceEntry{"tcp", 2004, "Graphite pickle metrics"},
    ServiceEntry{"tcp", 2006, "Graphite query service"},
    ServiceEntry{"tcp", 24224, "Fluentd forward input"},
    ServiceEntry{"tcp", 50051, "gRPC application service"},
    ServiceEntry{"tcp", 55000, "Wazuh manager API"},
    ServiceEntry{"udp", 1814, "RADIUS accounting (alternate)"},
    ServiceEntry{"udp", 3478, "STUN"},
    ServiceEntry{"udp", 3479, "STUN"},
    ServiceEntry{"udp", 3784, "BFD control"},
    ServiceEntry{"udp", 3785, "BFD echo"},
    ServiceEntry{"udp", 4789, "VXLAN overlay"},
    ServiceEntry{"udp", 5141, "Syslog (alternate)"},
    ServiceEntry{"udp", 7946, "Docker Swarm control"},
    ServiceEntry{"udp", 8125, "StatsD metrics"},
    ServiceEntry{"udp", 8126, "Datadog trace intake"},
    ServiceEntry{"udp", 9001, "Tor relay ORPort (common)"},
    ServiceEntry{"udp", 12201, "Graylog GELF input"},
    ServiceEntry{"udp", 24224, "Fluentd forward input"},
    ServiceEntry{"udp", 51821, "WireGuard (common alternate)"},
};

constexpr std::array service_ranges{
    ServiceRangeEntry{"tcp", 5900, 5999, "VNC remote desktop display range"},
    ServiceRangeEntry{"tcp", 6000, 6063, "X11 display server range"},
    ServiceRangeEntry{"tcp", 30000, 32767, "Kubernetes NodePort default range"},
    ServiceRangeEntry{"udp", 5900, 5999, "VNC remote desktop display range"},
    ServiceRangeEntry{"udp", 6000, 6063, "X11 display server range"},
    ServiceRangeEntry{"udp", 30000, 32767, "Kubernetes NodePort default range"},
};
} // namespace

std::optional<std::string_view> find_service(const std::string_view protocol, const unsigned short port) {
    for (const auto& entry : services) {
        if (entry.protocol == protocol && entry.port == port) return entry.label;
    }
    return std::nullopt;
}

std::optional<std::string_view> find_service_range(const std::string_view protocol, const unsigned short port) {
    for (const auto& entry : service_ranges) {
        if (entry.protocol == protocol && port >= entry.first_port && port <= entry.last_port) return entry.label;
    }
    return std::nullopt;
}

} // namespace ffc::port_catalog
