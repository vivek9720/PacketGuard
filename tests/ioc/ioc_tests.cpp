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

    IndicatorIndex index;
    index.add_set(set);
    auto indexed = index.lookup_ip(*packetguard::core::parse_ipv4("10.2.3.4"), "test.source");
    require_ioc(indexed.size() == 1, "stateful index CIDR lookup");
    auto domain_indicator = parse_indicator_line("domain,Example.NET,block", 4);
    require_ioc(domain_indicator.ok(), "stateful domain indicator parses");
    auto id = index.add(domain_indicator.value());
    require_ioc(!index.lookup_domain("www.example.net").empty(), "stateful index domain lookup");
    require_ioc(index.remove_id(id), "stateful index remove by id");
    require_ioc(index.lookup_domain("www.example.net").empty(), "stateful index remove affects lookup");
    require_ioc(index.reactivate_id(id), "stateful index reactivates record");
    require_ioc(!index.lookup_domain("www.example.net").empty(), "stateful index reactivated lookup");
    require_ioc(index.update_role(id, ListRole::allow), "stateful index role update");
    index.rebuild();
    require_ioc(index.validate_integrity(), "stateful index validates after rebuild");
    index.compact();
    require_ioc(index.stats().inactive_records == 0, "stateful index compact removes inactive records");
}
