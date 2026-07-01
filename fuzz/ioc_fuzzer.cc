#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    auto set = packetguard::ioc::parse_indicator_text(text, "fuzz-input");
    (void)packetguard::ioc::summarize_indicators(set);
    packetguard::packet::PacketMetadata md;
    md.ipv4 = packetguard::packet::IPv4Packet{};
    auto src = packetguard::core::parse_ipv4("192.168.1.10");
    auto dst = packetguard::core::parse_ipv4("8.8.8.8");
    if (src && dst) { md.ipv4->source = *src; md.ipv4->destination = *dst; }
    auto matches = packetguard::ioc::match_packet(set, md);
    (void)packetguard::ioc::summarize_matches(matches);
    if (!text.empty()) (void)packetguard::ioc::parse_indicator_line(text.substr(0, text.find('\n')), 1);
    return 0;
}
