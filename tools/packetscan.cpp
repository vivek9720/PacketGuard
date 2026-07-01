#include "packet/packet.hpp"
#include "ioc/ioc.hpp"
#include "rules/rules.hpp"
#include <exception>
#include <iostream>
#include <string>

static void usage() {
    std::cout << "usage: packetscan <pcap> [--ioc file] [--rules file]\n";
}
int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    std::string pcap_path = argv[1];
    std::string ioc_path;
    std::string rules_path;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--ioc" && i + 1 < argc) ioc_path = argv[++i];
        else if (arg == "--rules" && i + 1 < argc) rules_path = argv[++i];
        else { usage(); return 2; }
    }
    try {
        auto pcap = packetguard::packet::parse_pcap_file(pcap_path);
        if (!pcap) { std::cerr << pcap.status().message << "\n"; return 1; }
        std::cout << packetguard::packet::summarize_pcap(pcap.value());
        if (!ioc_path.empty()) {
            auto set = packetguard::ioc::parse_indicator_file(ioc_path);
            auto matches = packetguard::ioc::match_packets(set, pcap.value().packets);
            std::cout << packetguard::ioc::summarize_matches(matches);
        }
        if (!rules_path.empty()) {
            auto rf = packetguard::rules::parse_rule_file(rules_path);
            std::size_t hits = 0;
            for (const auto& pkt : pcap.value().packets) hits += packetguard::rules::matching_rules(rf, pkt.metadata).size();
            std::cout << "rule_packet_matches=" << hits << "\n";
            std::cout << packetguard::rules::summarize_rules(rf);
        }
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
    return 0;
}
