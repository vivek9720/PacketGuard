#include "rules/rule_set_manager.hpp"
#include "core/ip.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

std::string chunk_to_rule(const uint8_t* data, std::size_t size, std::uint32_t sid) {
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    for (char& c : text) {
        if (c == '\0' || c == '\r') c = ' ';
    }
    if (text.find('(') != std::string::npos && text.find(')') != std::string::npos) return text;
    static const char* protocols[] = {"tcp", "udp", "ip", "dns", "http"};
    static const char* actions[] = {"alert", "pass", "drop", "reject"};
    auto protocol = protocols[size % 5];
    auto action = actions[(size / 3) % 4];
    std::uint16_t port = static_cast<std::uint16_t>((size * 37u + sid) % 65536u);
    return std::string(action) + " " + protocol + " any any -> any " + std::to_string(port) +
           " (msg:\"state fuzz " + std::to_string(sid) + "\"; content:\"" + text.substr(0, 24) +
           "\"; sid:" + std::to_string(200000u + sid) + "; rev:1; classtype:network-activity;)";
}

packetguard::packet::PacketMetadata sample_metadata(uint8_t selector) {
    packetguard::packet::PacketMetadata metadata;
    metadata.ipv4 = packetguard::packet::IPv4Packet{};
    auto src = packetguard::core::parse_ipv4((selector & 1) ? "10.1.2.3" : "192.168.1.10");
    auto dst = packetguard::core::parse_ipv4((selector & 2) ? "198.51.100.8" : "203.0.113.9");
    if (src && dst) {
        metadata.ipv4->source = *src;
        metadata.ipv4->destination = *dst;
    }
    if (selector & 4) {
        metadata.udp = packetguard::packet::UdpDatagram{};
        metadata.udp->source_port = 53000;
        metadata.udp->destination_port = 53;
    } else {
        metadata.tcp = packetguard::packet::TcpSegment{};
        metadata.tcp->source_port = 51000;
        metadata.tcp->destination_port = (selector & 8) ? 443 : 80;
    }
    return metadata;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    packetguard::rules::RuleSetManager manager;
    std::size_t offset = 0;
    std::uint32_t sid_seed = 1;
    while (offset < size) {
        uint8_t op = data[offset++];
        std::size_t available = size - offset;
        std::size_t take = available == 0 ? 0 : static_cast<std::size_t>(data[offset % size] % 48u);
        if (take > available) take = available;
        std::string rule = chunk_to_rule(data + offset, take, sid_seed++);
        switch (op % 9) {
            case 0:
                (void)manager.add_rule_text(rule);
                break;
            case 1:
                (void)manager.add_rule_file_text(rule + "\n" + chunk_to_rule(data + offset, take / 2, sid_seed++));
                break;
            case 2:
                if (!manager.empty()) (void)manager.replace_rule_text(op % manager.size(), rule);
                break;
            case 3:
                if (!manager.empty()) (void)manager.erase_index(op % manager.size());
                break;
            case 4:
                (void)manager.erase_sid(200000u + static_cast<std::uint32_t>(op));
                break;
            case 5: {
                auto snapshot = manager.snapshot();
                for (const auto& snapshot_rule : snapshot.rules) {
                    (void)packetguard::rules::normalize_rule(snapshot_rule);
                }
                break;
            }
            case 6:
                (void)manager.find_latest_sid(200000u + static_cast<std::uint32_t>(op));
                break;
            case 7:
                (void)manager.find_by_classtype("network-activity");
                break;
            default: {
                auto metadata = sample_metadata(op);
                (void)manager.match_packet(metadata);
                (void)manager.summary();
                break;
            }
        }
        offset += take;
        if (manager.size() > 128) manager.clear();
    }
    auto metadata = sample_metadata(static_cast<uint8_t>(size));
    (void)manager.match_packet(metadata);
    (void)manager.snapshot();
    return 0;
}
