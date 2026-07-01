#include "rules/rules.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    auto file = packetguard::rules::parse_rule_text(text);
    (void)packetguard::rules::summarize_rules(file);
    packetguard::packet::PacketMetadata md;
    md.ipv4 = packetguard::packet::IPv4Packet{};
    auto src = packetguard::core::parse_ipv4("10.1.2.3");
    auto dst = packetguard::core::parse_ipv4("192.168.1.20");
    if (src && dst) { md.ipv4->source = *src; md.ipv4->destination = *dst; }
    md.tcp = packetguard::packet::TcpSegment{};
    md.tcp->source_port = 51515;
    md.tcp->destination_port = 80;
    for (const auto& rule : file.rules) {
        (void)packetguard::rules::validate_rule(rule);
        (void)packetguard::rules::normalize_rule(rule);
        (void)packetguard::rules::rule_matches_packet(rule, md);
    }
    return 0;
}
