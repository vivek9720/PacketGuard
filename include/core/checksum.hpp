#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include "core/byte_view.hpp"
#include "core/ip.hpp"

namespace packetguard::core {
std::uint16_t internet_checksum(ByteView bytes, std::uint32_t initial = 0);
std::uint32_t crc32(ByteView bytes);
std::uint16_t ipv4_header_checksum(ByteView header);
std::uint16_t tcp_udp_checksum(IPv4Address src, IPv4Address dst, std::uint8_t protocol, ByteView segment);
} // namespace packetguard::core
