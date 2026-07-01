#pragma once
#include <cstdint>

namespace packetguard::core {
inline std::uint16_t bswap16(std::uint16_t v) { return static_cast<std::uint16_t>((v >> 8) | (v << 8)); }
inline std::uint32_t bswap32(std::uint32_t v) { return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) | ((v & 0x00ff0000u) >> 8) | ((v & 0xff000000u) >> 24); }
inline std::uint16_t read_be16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }
inline std::uint32_t read_be32(const std::uint8_t* p) { return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) | (static_cast<std::uint32_t>(p[2]) << 8) | p[3]; }
inline std::uint16_t read_le16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] | (p[1] << 8)); }
inline std::uint32_t read_le32(const std::uint8_t* p) { return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) | (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24); }
} // namespace packetguard::core
