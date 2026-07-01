#include "packet/packet.hpp"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

static void require_packet(bool value, const std::string& message) {
    if (!value) { std::cerr << "test failed: " << message << "\n"; std::exit(1); }
}

static std::vector<std::uint8_t> dns_pcap() {
    return {
        0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0x01,0,0,0,
        0x01,0,0,0,0,0,0,0,0x4a,0,0,0,0x4a,0,0,0,
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0x08,0x00,
        0x45,0x00,0x00,0x3c,0x00,0x01,0x00,0x00,0x40,0x11,0x00,0x00,0xc0,0xa8,0x01,0x0a,0x08,0x08,0x08,0x08,
        0xc0,0x00,0x00,0x35,0x00,0x28,0x00,0x00,
        0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,0x00,0x01,0x00,0x01
    };
}

void run_packet_tests() {
    using namespace packetguard::packet;
    auto bytes = dns_pcap();
    auto pcap = parse_pcap(packetguard::core::ByteView(bytes));
    require_packet(pcap.ok(), "parse PCAP");
    require_packet(pcap.value().packets.size() == 1, "one packet");
    const auto& md = pcap.value().packets[0].metadata;
    require_packet(md.ipv4.has_value(), "IPv4 decoded");
    require_packet(md.udp.has_value(), "UDP decoded");
    require_packet(md.dns.has_value(), "DNS decoded");
    require_packet(!md.domain_names().empty() && md.domain_names()[0] == "example.com", "DNS name decoded");
    auto bad = parse_pcap(packetguard::core::ByteView(reinterpret_cast<const std::uint8_t*>("bad"), 3));
    require_packet(!bad.ok(), "reject short PCAP");
}
