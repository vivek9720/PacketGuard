#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

class FuzzReader {
public:
    FuzzReader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}
    bool empty() const { return offset_ >= size_; }
    std::uint8_t byte() {
        if (empty()) return 0;
        return data_[offset_++];
    }
    std::string text(std::size_t max_len) {
        std::size_t len = byte() % (max_len + 1);
        len = std::min(len, size_ - offset_);
        std::string out(reinterpret_cast<const char*>(data_ + offset_), reinterpret_cast<const char*>(data_ + offset_ + len));
        offset_ += len;
        return out;
    }
    std::uint32_t u32() {
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) value = (value << 8) | byte();
        return value;
    }
private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t offset_ = 0;
};

packetguard::ioc::Indicator fallback_indicator(std::uint8_t selector) {
    const char* samples[] = {
        "10.0.0.0/8 block severity=medium",
        "192.168.1.0/24 allow severity=low",
        "domain,example.com,block,confidence=0.8",
        "url,https://updates.example.net/path,indicator",
        "hash,d41d8cd98f00b204e9800998ecf8427e,block"
    };
    auto parsed = packetguard::ioc::parse_indicator_line(samples[selector % 5], selector + 1);
    if (parsed) return parsed.value();
    return {};
}

packetguard::packet::PacketMetadata packet_from_reader(FuzzReader& reader) {
    packetguard::packet::PacketMetadata md;
    md.ipv4 = packetguard::packet::IPv4Packet{};
    md.ipv4->source = packetguard::core::IPv4Address{reader.u32()};
    md.ipv4->destination = packetguard::core::IPv4Address{reader.u32()};
    if ((reader.byte() & 1u) == 0) {
        md.tcp = packetguard::packet::TcpSegment{};
        md.tcp->source_port = static_cast<std::uint16_t>(reader.u32());
        md.tcp->destination_port = static_cast<std::uint16_t>(reader.u32());
        md.ipv4->protocol = 6;
    } else {
        md.udp = packetguard::packet::UdpDatagram{};
        md.udp->source_port = static_cast<std::uint16_t>(reader.u32());
        md.udp->destination_port = static_cast<std::uint16_t>(reader.u32());
        md.ipv4->protocol = 17;
    }
    return md;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzReader reader(data, size);
    packetguard::ioc::IndicatorIndex index;
    std::vector<std::uint64_t> ids;
    std::size_t operations = 0;

    while (!reader.empty() && operations++ < 256) {
        std::uint8_t op = reader.byte();
        switch (op % 10) {
            case 0: {
                auto line = reader.text(160);
                auto parsed = packetguard::ioc::parse_indicator_line(line, operations);
                auto id = index.add(parsed ? parsed.value() : fallback_indicator(op));
                ids.push_back(id);
                break;
            }
            case 1: {
                auto set = packetguard::ioc::parse_indicator_text(reader.text(384), "state-fuzz");
                auto before = index.stats().total_records;
                index.add_set(set);
                auto after = index.stats().total_records;
                for (std::size_t id = before + 1; id <= after; ++id) ids.push_back(static_cast<std::uint64_t>(id));
                break;
            }
            case 2:
                if (!ids.empty()) (void)index.remove_id(ids[reader.byte() % ids.size()]);
                break;
            case 3:
                if (!ids.empty()) (void)index.reactivate_id(ids[reader.byte() % ids.size()]);
                break;
            case 4:
                if (!ids.empty()) (void)index.update_role(ids[reader.byte() % ids.size()], static_cast<packetguard::ioc::ListRole>(reader.byte() % 3));
                break;
            case 5:
                (void)index.lookup_ip(packetguard::core::IPv4Address{reader.u32()}, "fuzz.ip");
                break;
            case 6:
                (void)index.lookup_domain(reader.text(120), "fuzz.domain");
                break;
            case 7:
                (void)index.lookup_hash(reader.text(160), "fuzz.hash");
                break;
            case 8: {
                auto md = packet_from_reader(reader);
                (void)index.match_packet(md);
                break;
            }
            default:
                if (reader.byte() & 1u) index.rebuild();
                else index.compact();
                break;
        }
        packetguard::core::Diagnostics diagnostics;
        (void)index.validate_integrity(&diagnostics);
        (void)index.stats();
    }
    return 0;
}
