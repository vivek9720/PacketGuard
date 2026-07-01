#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
#include <exception>
#include <iostream>
#include <string>

static void usage() { std::cout << "usage: iocmatch <ioc-file> [pcap]\n"; }
int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    try {
        auto set = packetguard::ioc::parse_indicator_file(argv[1]);
        std::cout << packetguard::ioc::summarize_indicators(set);
        if (argc >= 3) {
            auto pcap = packetguard::packet::parse_pcap_file(argv[2]);
            if (!pcap) { std::cerr << pcap.status().message << "\n"; return 1; }
            auto matches = packetguard::ioc::match_packets(set, pcap.value().packets);
            std::cout << packetguard::ioc::summarize_matches(matches);
        }
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
    return 0;
}
