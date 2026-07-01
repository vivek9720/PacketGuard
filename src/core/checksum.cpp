#include "core/checksum.hpp"

namespace packetguard::core {

std::uint16_t internet_checksum(ByteView bytes, std::uint32_t initial) {
    std::uint32_t sum = initial;
    const auto* p = bytes.data();
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) sum += static_cast<std::uint16_t>((p[i] << 8) | p[i + 1]);
    if (bytes.size() & 1) sum += static_cast<std::uint16_t>(p[bytes.size() - 1] << 8);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}
std::uint32_t crc32(ByteView bytes) {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        crc ^= bytes.data()[i];
        for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
std::uint16_t ipv4_header_checksum(ByteView header) { return internet_checksum(header); }
std::uint16_t tcp_udp_checksum(IPv4Address src, IPv4Address dst, std::uint8_t protocol, ByteView segment) {
    std::uint32_t sum = 0;
    sum += (src.value >> 16) & 0xffffu; sum += src.value & 0xffffu;
    sum += (dst.value >> 16) & 0xffffu; sum += dst.value & 0xffffu;
    sum += protocol;
    sum += static_cast<std::uint32_t>(segment.size());
    return internet_checksum(segment, sum);
}

} // namespace packetguard::core
