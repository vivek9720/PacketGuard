#include "core/byte_view.hpp"
#include "core/checksum.hpp"
#include "core/ip.hpp"
#include "core/strings.hpp"
#include "core/time.hpp"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

void run_packet_tests();
void run_ioc_tests();
void run_rules_tests();
void run_policy_tests();

static void require(bool value, const std::string& message) {
    if (!value) { std::cerr << "test failed: " << message << "\n"; std::exit(1); }
}

void run_core_tests() {
    using namespace packetguard::core;
    auto ip = parse_ipv4("192.168.1.10");
    require(ip.has_value(), "parse IPv4");
    require(ipv4_to_string(*ip) == "192.168.1.10", "format IPv4");
    auto cidr = parse_cidr("192.168.1.0/24");
    require(cidr.has_value() && cidr->contains(*ip), "CIDR contains IP");
    require(!parse_ipv4("999.1.1.1"), "reject invalid IPv4");
    require(!parse_cidr("10.0.0.0/999999999999999999999999999999"), "reject oversized CIDR prefix");
    require(to_lower("AbC") == "abc", "lowercase");
    require(trim("  x \r\n") == "x", "trim");
    std::vector<std::uint8_t> bytes = {0x45,0x00,0x00,0x14,0,0,0,0,64,6,0,0,127,0,0,1,127,0,0,1};
    auto csum = ipv4_header_checksum(ByteView(bytes));
    require(csum != 0, "checksum computed");
    auto ts = parse_unix_timestamp("10.5");
    require(ts && ts->seconds == 10 && ts->nanos == 500000000, "timestamp parse");
    ByteReader reader(ByteView(bytes));
    auto b = reader.read_u8();
    require(b && b.value() == 0x45, "byte reader u8");
}

int main() {
    run_core_tests();
    run_packet_tests();
    run_ioc_tests();
    run_rules_tests();
    run_policy_tests();
    std::cout << "all tests passed\n";
    return 0;
}
