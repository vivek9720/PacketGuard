#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

static std::vector<std::string> split_refresh_stages(const std::string& text) {
    std::vector<std::string> stages;
    std::size_t start = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\f') {
            stages.push_back(text.substr(start, i - start));
            start = i + 1;
        }
    }
    stages.push_back(text.substr(start));
    if (stages.size() == 1 && text.size() > 8) {
        stages.clear();
        stages.push_back(text.substr(0, text.size() / 2));
        stages.push_back(text.substr(text.size() / 2));
    }
    return stages;
}

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
    auto stages = split_refresh_stages(text);
    if (!stages.empty()) {
        packetguard::ioc::IndicatorRefreshSession session;
        session.ingest_snapshot(stages.front(), "stage-0");
        for (std::size_t i = 1; i < stages.size(); ++i) {
            session.replace_snapshot(stages[i], "stage-" + std::to_string(i));
            if (src) {
                auto cached = session.match_cached_cidr(*src, "refresh.probe");
                (void)packetguard::ioc::summarize_matches(cached);
            }
        }
        (void)session.stats();
    }
    return 0;
}
