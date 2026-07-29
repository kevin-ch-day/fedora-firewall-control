#include "ffc/port_intelligence.hpp"
#include "port_catalog.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <map>
#include <netdb.h>

namespace ffc {
namespace {
const std::map<std::string, std::string> service_names{
    // Curated entries prioritize exposed management, discovery, data, and
    // infrastructure services that are useful in defensive triage.
    {"tcp/1", "TCP Port Service Multiplexer"},
    {"tcp/5", "Remote Job Entry"}, {"tcp/7", "Echo diagnostic"},
    {"tcp/9", "Discard diagnostic"}, {"tcp/11", "Systat diagnostic"},
    {"tcp/13", "Daytime"}, {"tcp/17", "Quote of the Day"},
    {"tcp/19", "Chargen diagnostic"}, {"tcp/20", "FTP data"},
    {"tcp/21", "FTP control"}, {"tcp/22", "SSH remote administration"},
    {"tcp/23", "Telnet remote administration"}, {"tcp/25", "SMTP mail transfer"},
    {"tcp/37", "Time service"}, {"tcp/42", "host name service"},
    {"tcp/43", "WHOIS"}, {"tcp/49", "TACACS+ administration"},
    {"tcp/53", "DNS"}, {"tcp/70", "Gopher"}, {"tcp/79", "Finger"},
    {"tcp/80", "HTTP"}, {"tcp/81", "alternate HTTP"},
    {"tcp/88", "Kerberos"}, {"tcp/102", "ISO-TSAP"},
    {"tcp/110", "POP3"}, {"tcp/111", "RPCbind"}, {"tcp/113", "Ident"},
    {"tcp/119", "NNTP"}, {"tcp/135", "MS RPC endpoint mapper"},
    {"tcp/139", "NetBIOS session"}, {"tcp/143", "IMAP"},
    {"tcp/150", "Netstat service"}, {"tcp/179", "BGP routing"},
    {"tcp/194", "IRC"}, {"tcp/199", "SNMP over TCP"},
    {"tcp/210", "Z39.50 information retrieval"}, {"tcp/220", "IMAP3"},
    {"tcp/264", "BGMP routing"}, {"tcp/311", "AppleShare IP web administration"},
    {"tcp/318", "TSP time synchronization"}, {"tcp/350", "MATIP"},
    {"tcp/371", "ClearCase version manager"}, {"tcp/389", "LDAP"},
    {"tcp/406", "IMSP"}, {"tcp/427", "Service Location Protocol"},
    {"tcp/443", "HTTPS"}, {"tcp/444", "SNPP paging"},
    {"tcp/445", "SMB file sharing"}, {"tcp/464", "Kerberos password change"},
    {"tcp/465", "SMTP submission over TLS"}, {"tcp/497", "retrospect backup"},
    {"tcp/500", "IKE/IPsec key exchange"}, {"tcp/502", "Modbus industrial control"},
    {"tcp/512", "rexec remote administration"}, {"tcp/513", "rlogin remote administration"},
    {"tcp/514", "rsh remote administration"}, {"tcp/515", "LPD printing"},
    {"tcp/540", "UUCP"}, {"tcp/543", "Kerberos login"},
    {"tcp/544", "Kerberos shell"}, {"tcp/548", "AFP file sharing"},
    {"tcp/554", "RTSP media streaming"}, {"tcp/560", "rmonitor"},
    {"tcp/563", "NNTP over TLS"}, {"tcp/587", "SMTP submission"},
    {"tcp/593", "HTTP RPC endpoint mapper"}, {"tcp/604", "TUNNEL profile"},
    {"tcp/623", "IPMI/RMCP"}, {"tcp/625", "Apple Xsan management"},
    {"tcp/631", "IPP printing"}, {"tcp/636", "LDAPS"},
    {"tcp/646", "LDP/MPLS"}, {"tcp/651", "IEEE-MMS"},
    {"tcp/657", "RMC"}, {"tcp/666", "Doom game service"},
    {"tcp/694", "Linux-HA cluster"}, {"tcp/749", "Kerberos administration"},
    {"tcp/750", "Kerberos IV"}, {"tcp/751", "Kerberos password service"},
    {"tcp/754", "Kerberos V password service"}, {"tcp/760", "Kerberos IV database"},
    {"tcp/783", "SpamAssassin"}, {"tcp/800", "MDBS database"},
    {"tcp/853", "DNS over TLS"}, {"tcp/860", "iSCSI"},
    {"tcp/873", "rsync"}, {"tcp/902", "VMware management"},
    {"tcp/911", "xact-backup"}, {"tcp/912", "Apex mesh"},
    {"tcp/989", "FTPS data"}, {"tcp/990", "FTPS control"},
    {"tcp/993", "IMAPS"}, {"tcp/995", "POP3S"},
    {"tcp/1025", "commonly dynamic MS RPC service"}, {"tcp/1026", "commonly dynamic MS RPC service"},
    {"tcp/1027", "commonly dynamic MS RPC service"}, {"tcp/1028", "commonly dynamic MS RPC service"},
    {"tcp/1080", "SOCKS proxy"}, {"tcp/1099", "Java RMI"},
    {"tcp/1311", "Dell OpenManage"}, {"tcp/1352", "Lotus Notes"},
    {"tcp/1433", "Microsoft SQL Server"}, {"tcp/1494", "Citrix ICA"},
    {"tcp/1500", "VLSI License Manager"}, {"tcp/1521", "Oracle database"},
    {"tcp/1604", "Citrix ICA management"}, {"tcp/1720", "H.323 call signaling"},
    {"tcp/1723", "PPTP VPN"}, {"tcp/1701", "L2TP VPN"},
    {"tcp/1801", "Microsoft Message Queuing"}, {"tcp/1883", "MQTT"},
    {"tcp/1935", "RTMP media streaming"}, {"tcp/2000", "Cisco SCCP"},
    {"tcp/2049", "NFS file sharing"}, {"tcp/2083", "RadSec"},
    {"tcp/2100", "Oracle XDB"}, {"tcp/2181", "ZooKeeper"},
    {"tcp/2375", "Docker API (unencrypted)"}, {"tcp/2376", "Docker API (TLS)"},
    {"tcp/2379", "etcd client API"}, {"tcp/2380", "etcd peer API"},
    {"tcp/2404", "IEC 60870-5-104 industrial control"}, {"tcp/2483", "Oracle database"},
    {"tcp/2484", "Oracle database over TLS"}, {"tcp/2638", "Sybase database"},
    {"tcp/2809", "IBM WebSphere IIOP"}, {"tcp/3000", "development web service"},
    {"tcp/3128", "HTTP proxy"}, {"tcp/3260", "iSCSI storage"},
    {"tcp/3268", "Active Directory global catalog"}, {"tcp/3269", "Active Directory global catalog over TLS"},
    {"tcp/3306", "MySQL/MariaDB"}, {"tcp/3389", "RDP remote desktop"},
    {"tcp/3478", "STUN"}, {"tcp/3690", "Subversion"},
    {"tcp/4000", "development web service"}, {"tcp/4369", "Erlang Port Mapper"},
    {"tcp/44818", "EtherNet/IP industrial control"}, {"tcp/4840", "OPC UA industrial control"},
    {"tcp/5000", "development web service"}, {"tcp/5060", "SIP signaling"},
    {"tcp/5061", "SIP signaling over TLS"}, {"tcp/5222", "XMPP client"},
    {"tcp/5223", "XMPP client over TLS"}, {"tcp/5269", "XMPP server federation"},
    {"tcp/5432", "PostgreSQL"}, {"tcp/5601", "Kibana web service"},
    {"tcp/5671", "AMQP over TLS"}, {"tcp/5672", "AMQP"},
    {"tcp/5684", "CoAP over TCP"}, {"tcp/5900", "VNC remote desktop"},
    {"tcp/5984", "CouchDB"}, {"tcp/5985", "WinRM remote administration"},
    {"tcp/5986", "WinRM over TLS"}, {"tcp/6000", "X11 display server"},
    {"tcp/6080", "noVNC web console"}, {"tcp/6379", "Redis"},
    {"tcp/6380", "Redis over TLS"}, {"tcp/6443", "Kubernetes API"},
    {"tcp/6667", "IRC"}, {"tcp/6697", "IRC over TLS"},
    {"tcp/7000", "AFS file service"}, {"tcp/7001", "WebLogic application server"},
    {"tcp/7100", "X font server"}, {"tcp/7199", "Cassandra JMX"},
    {"tcp/7474", "Neo4j web service"}, {"tcp/7547", "TR-069 management"},
    {"tcp/7687", "Neo4j Bolt"}, {"tcp/8000", "alternate HTTP"},
    {"tcp/8008", "alternate HTTP"}, {"tcp/8009", "AJP application connector"},
    {"tcp/8032", "Hadoop YARN web service"}, {"tcp/8080", "alternate HTTP"},
    {"tcp/8081", "alternate HTTP"}, {"tcp/8088", "alternate HTTP"},
    {"tcp/8090", "alternate HTTP"}, {"tcp/8161", "ActiveMQ web console"},
    {"tcp/8181", "alternate HTTP"}, {"tcp/8333", "Bitcoin peer-to-peer"},
    {"tcp/8443", "alternate HTTPS"}, {"tcp/8500", "Consul API"},
    {"tcp/8600", "Consul DNS"}, {"tcp/8888", "alternate HTTP/proxy"},
    {"tcp/9000", "application/admin service"}, {"tcp/9042", "Cassandra database"},
    {"tcp/9090", "monitoring/application web service"}, {"tcp/9092", "Kafka"},
    {"tcp/9093", "Alertmanager"}, {"tcp/9100", "JetDirect printing"},
    {"tcp/9153", "Tor metrics"}, {"tcp/9160", "Cassandra Thrift"},
    {"tcp/9200", "Elasticsearch REST API"}, {"tcp/9300", "Elasticsearch transport"},
    {"tcp/9418", "Git protocol"}, {"tcp/9997", "Splunk forwarding"},
    {"tcp/10000", "Webmin administration"}, {"tcp/10050", "Zabbix agent"},
    {"tcp/10051", "Zabbix server"}, {"tcp/10250", "Kubernetes kubelet API"},
    {"tcp/10257", "Kubernetes controller manager"}, {"tcp/10259", "Kubernetes scheduler"},
    {"tcp/11371", "OpenPGP keyserver"}, {"tcp/15672", "RabbitMQ management web service"},
    {"tcp/27017", "MongoDB database"}, {"tcp/28017", "MongoDB web status (legacy)"},
    {"tcp/50000", "SAP application service"}, {"tcp/50070", "Hadoop NameNode web service"},
    {"tcp/61616", "ActiveMQ"},
    {"udp/1", "TCP Port Service Multiplexer"}, {"udp/7", "Echo diagnostic"},
    {"udp/9", "Discard diagnostic"}, {"udp/13", "Daytime"},
    {"udp/17", "Quote of the Day"}, {"udp/19", "Chargen diagnostic"},
    {"udp/37", "Time service"}, {"udp/42", "host name service"},
    {"udp/43", "WHOIS"}, {"udp/49", "TACACS+ administration"},
    {"udp/53", "DNS"}, {"udp/67", "DHCP server"},
    {"udp/68", "DHCP client"}, {"udp/69", "TFTP"},
    {"udp/88", "Kerberos"}, {"udp/111", "RPCbind"},
    {"udp/123", "NTP"}, {"udp/135", "MS RPC endpoint mapper"},
    {"udp/137", "NetBIOS name service"}, {"udp/138", "NetBIOS datagram"},
    {"udp/161", "SNMP"}, {"udp/162", "SNMP trap"},
    {"udp/177", "XDMCP display manager"}, {"udp/194", "IRC"},
    {"udp/199", "SNMP over UDP"}, {"udp/389", "CLDAP"},
    {"udp/427", "Service Location Protocol"}, {"udp/500", "IKE/IPsec key exchange"},
    {"udp/512", "rexec remote administration"}, {"udp/513", "rlogin remote administration"},
    {"udp/514", "syslog"}, {"udp/520", "RIP routing"},
    {"udp/546", "DHCPv6 client"}, {"udp/547", "DHCPv6 server"},
    {"udp/548", "AFP file sharing"}, {"udp/554", "RTSP media streaming"},
    {"udp/560", "rmonitor"}, {"udp/623", "IPMI/RMCP"},
    {"udp/631", "IPP printing"}, {"udp/646", "LDP/MPLS"},
    {"udp/989", "FTPS data"}, {"udp/990", "FTPS control"},
    {"udp/1194", "OpenVPN"}, {"udp/1434", "Microsoft SQL Server Browser"},
    {"udp/1645", "RADIUS authentication (legacy)"}, {"udp/1646", "RADIUS accounting (legacy)"},
    {"udp/1701", "L2TP VPN"}, {"udp/1812", "RADIUS authentication"},
    {"udp/1813", "RADIUS accounting"}, {"udp/1900", "SSDP discovery"},
    {"udp/1985", "Cisco HSRP"}, {"udp/2049", "NFS file sharing"},
    {"udp/2222", "DirectPlay"}, {"udp/2427", "Media gateway control"},
    {"udp/3283", "Apple Remote Desktop"}, {"udp/3478", "STUN"},
    {"udp/3479", "STUN"}, {"udp/3544", "Teredo tunneling"},
    {"udp/3702", "WS-Discovery"}, {"udp/3784", "BFD control"},
    {"udp/3785", "BFD echo"}, {"udp/3799", "RADIUS dynamic authorization"},
    {"udp/4500", "IPsec NAT traversal"}, {"udp/4789", "VXLAN overlay"},
    {"udp/4840", "OPC UA industrial control"}, {"udp/5004", "RTP media"},
    {"udp/5005", "RTCP media control"}, {"udp/5060", "SIP signaling"},
    {"udp/5061", "SIP signaling over TLS"}, {"udp/5353", "mDNS discovery"},
    {"udp/5355", "LLMNR"}, {"udp/5683", "CoAP"},
    {"udp/5684", "CoAP over DTLS"}, {"udp/6081", "XMPP connection manager"},
    {"udp/6343", "sFlow telemetry"}, {"udp/6881", "BitTorrent"},
    {"udp/8472", "Flannel VXLAN"}, {"udp/8600", "Consul DNS"},
    {"udp/9993", "ZeroTier"}, {"udp/11211", "memcached"},
    {"udp/20000", "DNP3 industrial control"}, {"udp/33434", "traceroute (typical first probe)"},
    {"udp/44818", "EtherNet/IP industrial control"}, {"udp/47808", "BACnet building automation"},
    {"udp/51820", "WireGuard"},
    {"sctp/2905", "M3UA signaling"}, {"sctp/36412", "S1AP cellular signaling"},
    {"sctp/36422", "X2AP cellular signaling"}, {"sctp/38412", "NGAP 5G signaling"},
    {"sctp/3868", "Diameter"},
};

std::string normalized_protocol(std::string protocol) {
    std::transform(protocol.begin(), protocol.end(), protocol.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return protocol;
}

std::optional<unsigned short> parse_port(const std::string& value) {
    unsigned int parsed{}; const auto [position, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    return error == std::errc{} && position == value.data() + value.size() && parsed <= 65535U ? std::optional<unsigned short>(static_cast<unsigned short>(parsed)) : std::nullopt;
}
}

PortIntel identify_port(unsigned short port, const std::string& protocol) {
    const auto normalized = normalized_protocol(protocol);
    PortIntel intel{port, std::nullopt, normalized, port <= 1023 ? PortRange::WellKnown : port <= 49151 ? PortRange::Registered : PortRange::DynamicPrivate, {}, PortKnowledgeSource::RangeOnly};
    const auto service = service_names.find(normalized + "/" + std::to_string(port));
    if (service != service_names.end()) {
        intel.likely_service = service->second;
        intel.source = PortKnowledgeSource::Curated;
        return intel;
    }

    if (const auto extended_service = port_catalog::find_service(normalized, port)) {
        intel.likely_service = std::string(*extended_service);
        intel.source = PortKnowledgeSource::Curated;
        return intel;
    }

    if (const auto ranged_service = port_catalog::find_service_range(normalized, port)) {
        intel.likely_service = std::string(*ranged_service);
        intel.source = PortKnowledgeSource::Curated;
        return intel;
    }

    // Fedora's local services database fills gaps beyond the defensive
    // catalogue without a network lookup or a bundled copy of the IANA list.
    if (const auto* system_service = getservbyport(htons(port), normalized.c_str()); system_service != nullptr && system_service->s_name != nullptr) {
        intel.likely_service = std::string(system_service->s_name) + " (local service database)";
        intel.source = PortKnowledgeSource::SystemServiceDatabase;
    }
    return intel;
}
PortIntel identify_port_spec(const std::string& port_spec) {
    const auto separator = port_spec.find('/');
    if (separator == std::string::npos) return {};
    const auto port_part = port_spec.substr(0, separator);
    const auto range_separator = port_part.find('-');
    if (range_separator == std::string::npos) {
        const auto port = parse_port(port_part);
        return port ? identify_port(*port, port_spec.substr(separator + 1)) : PortIntel{};
    }

    const auto first_port = parse_port(port_part.substr(0, range_separator));
    const auto last_port = parse_port(port_part.substr(range_separator + 1));
    if (!first_port || !last_port || *first_port > *last_port) return {};
    auto intel = identify_port(*first_port, port_spec.substr(separator + 1));
    intel.range_end = *last_port;
    intel.likely_service = "port range (individual services vary)";
    intel.source = PortKnowledgeSource::RangeOnly;
    return intel;
}
PortIntel identify_endpoint(const std::string& endpoint, const std::string& protocol) {
    const auto separator = endpoint.rfind(':');
    if (separator == std::string::npos) return {};
    const auto port = parse_port(endpoint.substr(separator + 1));
    return port ? identify_port(*port, protocol) : PortIntel{};
}
std::string port_range_label(PortRange range) {
    if (range == PortRange::WellKnown) return "well-known 0-1023";
    if (range == PortRange::Registered) return "registered 1024-49151";
    if (range == PortRange::DynamicPrivate) return "dynamic/private 49152-65535";
    return "unrecognized port";
}
std::string port_knowledge_source_label(PortKnowledgeSource source) {
    if (source == PortKnowledgeSource::Curated) return "defensive catalogue";
    if (source == PortKnowledgeSource::SystemServiceDatabase) return "local service database";
    return "range classification";
}
std::string port_intel_label(const PortIntel& intel) {
    if (!intel.port) return "port unavailable";
    const auto label = intel.likely_service.empty() ? "unmapped service" : intel.likely_service;
    if (!intel.range_end) return label + " • " + port_range_label(intel.range);
    const auto final_range = *intel.range_end <= 1023 ? intel.range : *intel.range_end <= 49151 ? PortRange::Registered : PortRange::DynamicPrivate;
    if (final_range == intel.range) return label + " • " + port_range_label(intel.range);
    return label + " • spans " + port_range_label(intel.range) + " to " + port_range_label(final_range);
}
} // namespace ffc
