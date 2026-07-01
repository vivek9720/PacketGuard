#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace packetguard::core {

struct IPv4Address {
    std::uint32_t value = 0;
    bool operator==(const IPv4Address& other) const { return value == other.value; }
    bool operator<(const IPv4Address& other) const { return value < other.value; }
};

struct CIDRRange {
    IPv4Address network;
    std::uint8_t prefix = 32;
    bool contains(IPv4Address ip) const;
    std::string to_string() const;
};

std::optional<IPv4Address> parse_ipv4(const std::string& text);
std::string ipv4_to_string(IPv4Address ip);
std::optional<CIDRRange> parse_cidr(const std::string& text);
bool is_private_ipv4(IPv4Address ip);
bool is_loopback_ipv4(IPv4Address ip);
bool is_multicast_ipv4(IPv4Address ip);
bool is_reserved_ipv4(IPv4Address ip);
std::string classify_ipv4(IPv4Address ip);
std::uint32_t cidr_mask(std::uint8_t prefix);
std::vector<CIDRRange> merge_ranges(std::vector<CIDRRange> ranges);

} // namespace packetguard::core
