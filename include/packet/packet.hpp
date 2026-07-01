#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "core/byte_view.hpp"
#include "core/diagnostics.hpp"
#include "core/ip.hpp"
#include "core/result.hpp"
#include "core/time.hpp"

namespace packetguard::packet {

struct MacAddress {
    std::uint8_t bytes[6]{};
    std::string to_string() const;
};

struct EthernetFrame {
    MacAddress destination;
    MacAddress source;
    std::uint16_t ether_type = 0;
    std::size_t header_length = 14;
};

struct IPv4Packet {
    std::uint8_t version = 4;
    std::uint8_t ihl = 0;
    std::uint8_t dscp_ecn = 0;
    std::uint16_t total_length = 0;
    std::uint16_t identification = 0;
    std::uint16_t flags_fragment = 0;
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint16_t header_checksum = 0;
    core::IPv4Address source;
    core::IPv4Address destination;
    bool checksum_valid = false;
    bool fragmented = false;
    std::size_t header_length = 0;
    std::size_t payload_length = 0;
};

struct TcpSegment {
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint32_t sequence = 0;
    std::uint32_t acknowledgment = 0;
    std::uint8_t data_offset = 0;
    std::uint16_t flags = 0;
    std::uint16_t window = 0;
    std::uint16_t checksum = 0;
    std::uint16_t urgent = 0;
    std::size_t payload_length = 0;
    std::vector<std::uint8_t> options;
    std::vector<std::string> flag_names() const;
};

struct UdpDatagram {
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint16_t length = 0;
    std::uint16_t checksum = 0;
    std::size_t payload_length = 0;
};

struct DnsQuestion {
    std::string name;
    std::uint16_t type = 0;
    std::uint16_t klass = 0;
};

struct DnsRecord {
    std::string name;
    std::uint16_t type = 0;
    std::uint16_t klass = 0;
    std::uint32_t ttl = 0;
    std::vector<std::uint8_t> data;
    std::string data_text;
};

struct DnsMessage {
    std::uint16_t id = 0;
    bool response = false;
    std::uint8_t opcode = 0;
    bool authoritative = false;
    bool truncated = false;
    bool recursion_desired = false;
    bool recursion_available = false;
    std::uint8_t rcode = 0;
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> additionals;
};

struct PacketMetadata {
    core::Timestamp timestamp;
    std::size_t original_length = 0;
    std::size_t captured_length = 0;
    std::optional<EthernetFrame> ethernet;
    std::optional<IPv4Packet> ipv4;
    std::optional<TcpSegment> tcp;
    std::optional<UdpDatagram> udp;
    std::optional<DnsMessage> dns;
    std::vector<std::string> notes;
    std::string flow_key() const;
    std::vector<std::string> domain_names() const;
};

struct PcapPacket {
    PacketMetadata metadata;
    std::vector<std::uint8_t> payload;
};

struct PcapFile {
    bool nanosecond_resolution = false;
    bool little_endian = true;
    std::uint16_t major = 2;
    std::uint16_t minor = 4;
    std::int32_t this_zone = 0;
    std::uint32_t snaplen = 0;
    std::uint32_t link_type = 0;
    std::vector<PcapPacket> packets;
    core::Diagnostics diagnostics;
};

core::Result<EthernetFrame> parse_ethernet(core::ByteView bytes, core::Diagnostics* diagnostics = nullptr);
core::Result<IPv4Packet> parse_ipv4_packet(core::ByteView bytes, core::Diagnostics* diagnostics = nullptr);
core::Result<TcpSegment> parse_tcp_segment(core::ByteView bytes, core::Diagnostics* diagnostics = nullptr);
core::Result<UdpDatagram> parse_udp_datagram(core::ByteView bytes, core::Diagnostics* diagnostics = nullptr);
core::Result<DnsMessage> parse_dns_message(core::ByteView bytes, core::Diagnostics* diagnostics = nullptr);
core::Result<PcapFile> parse_pcap(core::ByteView bytes);
core::Result<PcapFile> parse_pcap_file(const std::string& path);
PacketMetadata decode_packet_payload(core::Timestamp timestamp, core::ByteView bytes, std::size_t original_length, std::uint32_t link_type, core::Diagnostics* diagnostics = nullptr);
std::string summarize_packet(const PacketMetadata& metadata);
std::string summarize_pcap(const PcapFile& pcap);
std::string ether_type_name(std::uint16_t ether_type);
std::string ip_protocol_name(std::uint8_t protocol);
std::string dns_type_name(std::uint16_t type);
std::string service_name(std::uint16_t port, const std::string& protocol);
std::map<std::string, std::size_t> protocol_histogram(const PcapFile& pcap);

} // namespace packetguard::packet
