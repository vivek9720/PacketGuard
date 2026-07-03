#include "core/ip.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <sstream>

namespace packetguard::core {

std::uint32_t cidr_mask(std::uint8_t prefix) {
    if (prefix == 0) return 0;
    if (prefix >= 32) return 0xffffffffu;
    return 0xffffffffu << (32 - prefix);
}
bool CIDRRange::contains(IPv4Address ip) const { return (ip.value & cidr_mask(prefix)) == (network.value & cidr_mask(prefix)); }
std::string CIDRRange::to_string() const { return ipv4_to_string({network.value & cidr_mask(prefix)}) + "/" + std::to_string(prefix); }
std::optional<IPv4Address> parse_ipv4(const std::string& text) {
    auto parts = split(trim(text), '.', true);
    if (parts.size() != 4) return std::nullopt;
    std::uint32_t value = 0;
    for (const auto& part : parts) {
        if (!is_decimal(part) || part.size() > 3) return std::nullopt;
        int octet = std::stoi(part);
        if (octet < 0 || octet > 255) return std::nullopt;
        value = (value << 8) | static_cast<std::uint32_t>(octet);
    }
    return IPv4Address{value};
}
std::string ipv4_to_string(IPv4Address ip) {
    std::ostringstream out;
    out << ((ip.value >> 24) & 255) << "." << ((ip.value >> 16) & 255) << "." << ((ip.value >> 8) & 255) << "." << (ip.value & 255);
    return out.str();
}
static std::optional<std::uint8_t> parse_cidr_prefix(const std::string& text) {
    if (text.empty()) return std::nullopt;
    unsigned value = 0;
    for (char c : text) {
        value = value * 10u + static_cast<unsigned>(c - '0');
        if (value > 32u) return std::nullopt;
    }
    return static_cast<std::uint8_t>(value);
}
std::optional<CIDRRange> parse_cidr(const std::string& text) {
    auto parts = split(trim(text), '/', true);
    if (parts.size() == 1) {
        auto ip = parse_ipv4(parts[0]);
        if (!ip) return std::nullopt;
        return CIDRRange{*ip, 32};
    }
    if (parts.size() != 2 || !is_decimal(parts[1])) return std::nullopt;
    auto prefix = parse_cidr_prefix(parts[1]);
    if (!prefix) return std::nullopt;
    auto ip = parse_ipv4(parts[0]);
    if (!ip) return std::nullopt;
    return CIDRRange{IPv4Address{ip->value & cidr_mask(*prefix)}, *prefix};
}
bool is_private_ipv4(IPv4Address ip) {
    return CIDRRange{{0x0a000000u}, 8}.contains(ip) || CIDRRange{{0xac100000u}, 12}.contains(ip) || CIDRRange{{0xc0a80000u}, 16}.contains(ip);
}
bool is_loopback_ipv4(IPv4Address ip) { return CIDRRange{{0x7f000000u}, 8}.contains(ip); }
bool is_multicast_ipv4(IPv4Address ip) { return CIDRRange{{0xe0000000u}, 4}.contains(ip); }
bool is_reserved_ipv4(IPv4Address ip) {
    return CIDRRange{{0x00000000u}, 8}.contains(ip) || CIDRRange{{0x64400000u}, 10}.contains(ip) || CIDRRange{{0xc0000000u}, 24}.contains(ip) || CIDRRange{{0xc6336400u}, 24}.contains(ip) || CIDRRange{{0xcb007100u}, 24}.contains(ip) || CIDRRange{{0xf0000000u}, 4}.contains(ip);
}
std::string classify_ipv4(IPv4Address ip) {
    if (is_loopback_ipv4(ip)) return "loopback";
    if (is_private_ipv4(ip)) return "private";
    if (is_multicast_ipv4(ip)) return "multicast";
    if (is_reserved_ipv4(ip)) return "reserved";
    return "public";
}
std::vector<CIDRRange> merge_ranges(std::vector<CIDRRange> ranges) {
    std::sort(ranges.begin(), ranges.end(), [](const CIDRRange& a, const CIDRRange& b){ if (a.network.value != b.network.value) return a.network.value < b.network.value; return a.prefix < b.prefix; });
    std::vector<CIDRRange> out;
    for (const auto& r : ranges) {
        bool covered = false;
        for (const auto& existing : out) if (existing.prefix <= r.prefix && existing.contains(r.network)) { covered = true; break; }
        if (!covered) out.push_back(r);
    }
    return out;
}

} // namespace packetguard::core
