#include "ffc/network_route.hpp"

#include <arpa/inet.h>

namespace ffc {
NetworkAddressScope classify_network_address(const std::string& address) {
    in_addr ipv4{};
    if (inet_pton(AF_INET, address.c_str(), &ipv4) == 1) {
        const auto value = ntohl(ipv4.s_addr);
        const auto first = (value >> 24U) & 0xffU;
        const auto second = (value >> 16U) & 0xffU;
        const auto third = (value >> 8U) & 0xffU;
        if (first == 10U || (first == 172U && second >= 16U && second <= 31U) || (first == 192U && second == 168U)) return NetworkAddressScope::Private;
        if (first == 100U && second >= 64U && second <= 127U) return NetworkAddressScope::CarrierGradeNat;
        if (first == 127U) return NetworkAddressScope::Loopback;
        if (first == 169U && second == 254U) return NetworkAddressScope::LinkLocal;
        if (first >= 224U && first <= 239U) return NetworkAddressScope::Multicast;
        if (first == 0U || first >= 240U || (first == 192U && second == 0U && (third == 0U || third == 2U)) || (first == 198U && (second == 18U || second == 19U || (second == 51U && third == 100U))) || (first == 203U && second == 0U && third == 113U)) return NetworkAddressScope::SpecialUse;
        return NetworkAddressScope::Public;
    }
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
        if (IN6_IS_ADDR_V4MAPPED(&ipv6)) {
            char mapped_ipv4[INET_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET, &ipv6.s6_addr[12], mapped_ipv4, sizeof(mapped_ipv4))) return classify_network_address(mapped_ipv4);
        }
        const auto first = ipv6.s6_addr[0];
        const auto second = ipv6.s6_addr[1];
        if ((first & 0xfeU) == 0xfcU) return NetworkAddressScope::Private;
        if (first == 0xfeU && (second & 0xc0U) == 0x80U) return NetworkAddressScope::LinkLocal;
        if (first == 0xffU) return NetworkAddressScope::Multicast;
        if (IN6_IS_ADDR_LOOPBACK(&ipv6)) return NetworkAddressScope::Loopback;
        if (IN6_IS_ADDR_UNSPECIFIED(&ipv6) || (first == 0x20U && second == 0x01U && ipv6.s6_addr[2] == 0x0dU && ipv6.s6_addr[3] == 0xb8U)) return NetworkAddressScope::SpecialUse;
        return NetworkAddressScope::Public;
    }
    return NetworkAddressScope::Unknown;
}

std::string network_address_scope_label(const NetworkAddressScope scope) {
    switch (scope) {
    case NetworkAddressScope::Private: return "private/local address";
    case NetworkAddressScope::CarrierGradeNat: return "carrier-grade NAT/provider address";
    case NetworkAddressScope::LinkLocal: return "link-local address";
    case NetworkAddressScope::Loopback: return "loopback address";
    case NetworkAddressScope::Multicast: return "multicast address";
    case NetworkAddressScope::SpecialUse: return "special-use address";
    case NetworkAddressScope::Public: return "publicly routable address";
    case NetworkAddressScope::Unknown: return "unclassified address";
    }
    return "unclassified address";
}
} // namespace ffc
