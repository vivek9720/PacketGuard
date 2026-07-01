#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
#include <cstdlib>
#include <iostream>
#include <string>

static void require_ioc(bool value, const std::string& message) {
    if (!value) { std::cerr << "test failed: " << message << "\n"; std::exit(1); }
}

void run_ioc_tests() {
    using namespace packetguard::ioc;
    auto one = parse_indicator_line("domain,Example.COM,block,severity=high,confidence=0.9", 1);
    require_ioc(one.ok(), "domain IOC parses");
    require_ioc(one.value().normalized == "example.com", "domain normalizes");
    auto set = parse_indicator_text("10.0.0.0/8 block\nexample.com block\nexample.com block\n");
    require_ioc(set.indicators.size() == 2, "dedupe indicators");
    packetguard::packet::PacketMetadata md;
    md.ipv4 = packetguard::packet::IPv4Packet{};
    md.ipv4->source = *packetguard::core::parse_ipv4("10.1.2.3");
    md.ipv4->destination = *packetguard::core::parse_ipv4("8.8.8.8");
    auto matches = match_packet(set, md);
    require_ioc(matches.size() == 1, "CIDR packet match");
    require_ioc(!parse_indicator_line("not an indicator", 2).ok(), "invalid indicator rejected");
}
