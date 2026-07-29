#include "ffc/network_route.hpp"

#include <arpa/inet.h>

namespace ffc {
NetworkAddressScope classify_network_address(const std::string& address) {
    in_addr ipv4{};
    if (inet_pton(AF_INET, address.c_str(), &ipv4) == 1) {
        const auto value = ntohl(ipv4.s_addr);
        const auto first = (value >> 24U) & 0xffU;
        const auto second = (value >> 16U) & 0xffU;
        if (first == 10U || (first == 172U && second >= 16U && second <= 31U) || (first == 192U && second == 168U)) return NetworkAddressScope::Private;
        if (first == 100U && second >= 64U && second <= 127U) return NetworkAddressScope::CarrierGradeNat;
        if (first == 127U) return NetworkAddressScope::Loopback;
        if (first == 169U && second == 254U) return NetworkAddressScope::LinkLocal;
        if (first >= 224U && first <= 239U) return NetworkAddressScope::Multicast;
        return NetworkAddressScope::Public;
    }
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
        const auto first = ipv6.s6_addr[0];
        const auto second = ipv6.s6_addr[1];
        if ((first & 0xfeU) == 0xfcU) return NetworkAddressScope::Private;
        if (first == 0xfeU && (second & 0xc0U) == 0x80U) return NetworkAddressScope::LinkLocal;
        if (first == 0xffU) return NetworkAddressScope::Multicast;
        if (IN6_IS_ADDR_LOOPBACK(&ipv6)) return NetworkAddressScope::Loopback;
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
    case NetworkAddressScope::Public: return "publicly routable address";
    case NetworkAddressScope::Unknown: return "unclassified address";
    }
    return "unclassified address";
}
} // namespace ffc
