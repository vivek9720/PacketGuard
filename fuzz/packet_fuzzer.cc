#include "packet/packet.hpp"
#include "ioc/ioc.hpp"
#include "rules/rules.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    packetguard::core::ByteView view(data, size);
    auto pcap = packetguard::packet::parse_pcap(view);
    if (pcap) {
        auto summary = packetguard::packet::summarize_pcap(pcap.value());
        auto indicators = packetguard::ioc::parse_indicator_text("8.8.8.8 block\nexample.com block\n10.0.0.0/8 allow\n");
        (void)packetguard::ioc::match_packets(indicators, pcap.value().packets);
        auto rules = packetguard::rules::parse_rule_text("alert udp any any -> any 53 (msg:\"dns\"; content:\"example\"; sid:1; rev:1;)\n");
        for (const auto& pkt : pcap.value().packets) (void)packetguard::rules::matching_rules(rules, pkt.metadata);
        (void)summary;
    } else if (size >= 14) {
        packetguard::core::Diagnostics diag;
        auto eth = packetguard::packet::parse_ethernet(view, &diag);
        if (eth && eth.value().ether_type == 0x0800 && size > eth.value().header_length) {
            auto ipview = view.slice(eth.value().header_length, size - eth.value().header_length);
            if (ipview) (void)packetguard::packet::parse_ipv4_packet(ipview.value(), &diag);
        }
    }
    return 0;
}
