#include "packet/packet.hpp"
#include "core/checksum.hpp"
#include "core/endian.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace packetguard::packet {
using namespace packetguard::core;

static bool has_bytes(ByteView bytes, std::size_t offset, std::size_t length) {
    return offset <= bytes.size() && length <= bytes.size() - offset;
}

std::string MacAddress::to_string() const {
    std::ostringstream out;
    for (int i = 0; i < 6; ++i) {
        if (i) out << ":";
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return out.str();
}
std::vector<std::string> TcpSegment::flag_names() const {
    std::vector<std::string> out;
    if (flags & 0x001) out.push_back("FIN");
    if (flags & 0x002) out.push_back("SYN");
    if (flags & 0x004) out.push_back("RST");
    if (flags & 0x008) out.push_back("PSH");
    if (flags & 0x010) out.push_back("ACK");
    if (flags & 0x020) out.push_back("URG");
    if (flags & 0x040) out.push_back("ECE");
    if (flags & 0x080) out.push_back("CWR");
    return out;
}
std::string PacketMetadata::flow_key() const {
    if (!ipv4) return {};
    std::ostringstream out;
    out << ipv4_to_string(ipv4->source) << ":";
    if (tcp) out << tcp->source_port; else if (udp) out << udp->source_port; else out << 0;
    out << " -> " << ipv4_to_string(ipv4->destination) << ":";
    if (tcp) out << tcp->destination_port << "/tcp"; else if (udp) out << udp->destination_port << "/udp"; else out << "0/" << ip_protocol_name(ipv4->protocol);
    return out.str();
}
std::vector<std::string> PacketMetadata::domain_names() const {
    std::vector<std::string> names;
    if (!dns) return names;
    for (const auto& q : dns->questions) names.push_back(q.name);
    for (const auto& r : dns->answers) if (!r.name.empty()) names.push_back(r.name);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

core::Result<EthernetFrame> parse_ethernet(ByteView bytes, Diagnostics* diagnostics) {
    if (bytes.size() < 14) return Status::failure("ethernet frame too short");
    EthernetFrame frame;
    std::copy(bytes.data(), bytes.data() + 6, frame.destination.bytes);
    std::copy(bytes.data() + 6, bytes.data() + 12, frame.source.bytes);
    frame.ether_type = read_be16(bytes.data() + 12);
    if (frame.ether_type == 0x8100 || frame.ether_type == 0x88a8) {
        if (bytes.size() < 18) return Status::failure("tagged ethernet frame too short");
        frame.ether_type = read_be16(bytes.data() + 16);
        frame.header_length = 18;
        if (diagnostics) diagnostics->info("ethernet.vlan", "VLAN tagged frame", 12);
    }
    return frame;
}
core::Result<IPv4Packet> parse_ipv4_packet(ByteView bytes, Diagnostics* diagnostics) {
    if (bytes.size() < 20) return Status::failure("ipv4 packet too short");
    IPv4Packet ip;
    ip.version = bytes.data()[0] >> 4;
    ip.ihl = bytes.data()[0] & 0x0f;
    if (ip.version != 4) return Status::failure("not an ipv4 packet");
    ip.header_length = static_cast<std::size_t>(ip.ihl) * 4;
    if (ip.ihl < 5 || ip.header_length > bytes.size()) return Status::failure("invalid ipv4 header length");
    ip.dscp_ecn = bytes.data()[1];
    ip.total_length = read_be16(bytes.data() + 2);
    if (ip.total_length < ip.header_length || ip.total_length > bytes.size()) {
        if (diagnostics) diagnostics->warn("ipv4.length", "IPv4 total length differs from captured bytes", 2);
        if (ip.total_length < ip.header_length) return Status::failure("invalid ipv4 total length");
        ip.total_length = static_cast<std::uint16_t>(bytes.size());
    }
    ip.identification = read_be16(bytes.data() + 4);
    ip.flags_fragment = read_be16(bytes.data() + 6);
    ip.ttl = bytes.data()[8];
    ip.protocol = bytes.data()[9];
    ip.header_checksum = read_be16(bytes.data() + 10);
    ip.source = IPv4Address{read_be32(bytes.data() + 12)};
    ip.destination = IPv4Address{read_be32(bytes.data() + 16)};
    ip.fragmented = (ip.flags_fragment & 0x3fffu) != 0 || (ip.flags_fragment & 0x2000u) != 0;
    auto hdr = bytes.slice(0, ip.header_length);
    ip.checksum_valid = hdr && internet_checksum(hdr.value()) == 0;
    ip.payload_length = ip.total_length - ip.header_length;
    if (ip.ttl == 0 && diagnostics) diagnostics->warn("ipv4.ttl", "IPv4 TTL is zero", 8);
    if (!ip.checksum_valid && diagnostics) diagnostics->warn("ipv4.checksum", "IPv4 header checksum did not validate", 10);
    return ip;
}
core::Result<TcpSegment> parse_tcp_segment(ByteView bytes, Diagnostics* diagnostics) {
    if (bytes.size() < 20) return Status::failure("tcp segment too short");
    TcpSegment tcp;
    tcp.source_port = read_be16(bytes.data());
    tcp.destination_port = read_be16(bytes.data() + 2);
    tcp.sequence = read_be32(bytes.data() + 4);
    tcp.acknowledgment = read_be32(bytes.data() + 8);
    tcp.data_offset = bytes.data()[12] >> 4;
    std::size_t header_len = static_cast<std::size_t>(tcp.data_offset) * 4;
    if (tcp.data_offset < 5 || header_len > bytes.size()) return Status::failure("invalid tcp data offset");
    tcp.flags = static_cast<std::uint16_t>(((bytes.data()[12] & 0x01) << 8) | bytes.data()[13]);
    tcp.window = read_be16(bytes.data() + 14);
    tcp.checksum = read_be16(bytes.data() + 16);
    tcp.urgent = read_be16(bytes.data() + 18);
    tcp.payload_length = bytes.size() - header_len;
    if (header_len > 20) tcp.options.assign(bytes.data() + 20, bytes.data() + header_len);
    if ((tcp.flags & 0x006) == 0x006 && diagnostics) diagnostics->warn("tcp.flags", "TCP SYN and RST both set", 13);
    return tcp;
}
core::Result<UdpDatagram> parse_udp_datagram(ByteView bytes, Diagnostics* diagnostics) {
    if (bytes.size() < 8) return Status::failure("udp datagram too short");
    UdpDatagram udp;
    udp.source_port = read_be16(bytes.data());
    udp.destination_port = read_be16(bytes.data() + 2);
    udp.length = read_be16(bytes.data() + 4);
    udp.checksum = read_be16(bytes.data() + 6);
    if (udp.length < 8) return Status::failure("invalid udp length");
    if (udp.length > bytes.size()) {
        if (diagnostics) diagnostics->warn("udp.length", "UDP length exceeds captured payload", 4);
        udp.length = static_cast<std::uint16_t>(bytes.size());
    }
    udp.payload_length = udp.length - 8;
    return udp;
}

static Result<std::string> read_dns_name(ByteView bytes, std::size_t& offset, int depth = 0) {
    if (depth > 12) return Status::failure("dns name compression loop");
    std::string name;
    while (true) {
        if (offset >= bytes.size()) return Status::failure("dns name outside message");
        std::uint8_t len = bytes.data()[offset++];
        if (len == 0) break;
        if ((len & 0xc0) == 0xc0) {
            if (offset >= bytes.size()) return Status::failure("dns compression pointer truncated");
            std::uint16_t ptr = static_cast<std::uint16_t>(((len & 0x3f) << 8) | bytes.data()[offset++]);
            std::size_t ptr_offset = ptr;
            auto suffix = read_dns_name(bytes, ptr_offset, depth + 1);
            if (!suffix) return suffix.status();
            if (!name.empty() && !suffix.value().empty()) name.push_back('.');
            name += suffix.value();
            break;
        }
        if (len & 0xc0) return Status::failure("invalid dns label marker");
        if (!has_bytes(bytes, offset, len)) return Status::failure("dns label outside message");
        if (!name.empty()) name.push_back('.');
        for (std::size_t i = 0; i < len; ++i) {
            unsigned char c = bytes.data()[offset + i];
            name.push_back((c >= 33 && c <= 126) ? static_cast<char>(std::tolower(c)) : '?');
        }
        offset += len;
        if (name.size() > 255) return Status::failure("dns name too long");
    }
    return name;
}
static Result<DnsQuestion> read_question(ByteView bytes, std::size_t& offset) {
    auto name = read_dns_name(bytes, offset);
    if (!name) return name.status();
    if (!has_bytes(bytes, offset, 4)) return Status::failure("dns question truncated");
    DnsQuestion q{name.value(), read_be16(bytes.data() + offset), read_be16(bytes.data() + offset + 2)};
    offset += 4;
    return q;
}
static std::string render_rdata(std::uint16_t type, ByteView message, ByteView data) {
    if (type == 1 && data.size() == 4) return ipv4_to_string({read_be32(data.data())});
    if ((type == 2 || type == 5 || type == 12) && data.size() > 0) {
        const auto message_begin = reinterpret_cast<std::uintptr_t>(message.data());
        const auto data_begin = reinterpret_cast<std::uintptr_t>(data.data());
        if (!message.data() || !data.data() || data_begin < message_begin || data.size() > message.size() || data_begin - message_begin > message.size() - data.size()) {
            return bytes_to_hex(data.data(), data.size());
        }
        std::size_t off = static_cast<std::size_t>(data.data() - message.data());
        auto name = read_dns_name(message, off);
        if (name) return name.value();
    }
    if (type == 16 && data.size() > 1) {
        std::string txt;
        std::size_t off = 0;
        while (off < data.size()) {
            std::uint8_t len = data.data()[off++];
            if (len > data.size() - off) break;
            if (!txt.empty()) txt.push_back(' ');
            txt.append(reinterpret_cast<const char*>(data.data() + off), reinterpret_cast<const char*>(data.data() + off + len));
            off += len;
        }
        return txt;
    }
    return bytes_to_hex(data.data(), data.size());
}
static Result<DnsRecord> read_record(ByteView bytes, std::size_t& offset) {
    auto name = read_dns_name(bytes, offset);
    if (!name) return name.status();
    if (!has_bytes(bytes, offset, 10)) return Status::failure("dns record truncated");
    DnsRecord r;
    r.name = name.value();
    r.type = read_be16(bytes.data() + offset);
    r.klass = read_be16(bytes.data() + offset + 2);
    r.ttl = read_be32(bytes.data() + offset + 4);
    std::uint16_t len = read_be16(bytes.data() + offset + 8);
    offset += 10;
    if (!has_bytes(bytes, offset, len)) return Status::failure("dns rdata truncated");
    r.data.assign(bytes.data() + offset, bytes.data() + offset + len);
    auto view = bytes.slice(offset, len);
    if (view) r.data_text = render_rdata(r.type, bytes, view.value());
    offset += len;
    return r;
}
core::Result<DnsMessage> parse_dns_message(ByteView bytes, Diagnostics* diagnostics) {
    if (bytes.size() < 12) return Status::failure("dns message too short");
    DnsMessage msg;
    std::size_t offset = 0;
    msg.id = read_be16(bytes.data());
    std::uint16_t flags = read_be16(bytes.data() + 2);
    msg.response = flags & 0x8000;
    msg.opcode = static_cast<std::uint8_t>((flags >> 11) & 0x0f);
    msg.authoritative = flags & 0x0400;
    msg.truncated = flags & 0x0200;
    msg.recursion_desired = flags & 0x0100;
    msg.recursion_available = flags & 0x0080;
    msg.rcode = static_cast<std::uint8_t>(flags & 0x0f);
    std::uint16_t qd = read_be16(bytes.data() + 4), an = read_be16(bytes.data() + 6), ns = read_be16(bytes.data() + 8), ar = read_be16(bytes.data() + 10);
    offset = 12;
    for (std::uint16_t i = 0; i < qd; ++i) { auto q = read_question(bytes, offset); if (!q) return q.status(); msg.questions.push_back(q.value()); }
    for (std::uint16_t i = 0; i < an; ++i) { auto r = read_record(bytes, offset); if (!r) return r.status(); msg.answers.push_back(r.value()); }
    for (std::uint16_t i = 0; i < ns; ++i) { auto r = read_record(bytes, offset); if (!r) return r.status(); msg.authorities.push_back(r.value()); }
    for (std::uint16_t i = 0; i < ar; ++i) { auto r = read_record(bytes, offset); if (!r) return r.status(); msg.additionals.push_back(r.value()); }
    if (msg.truncated && diagnostics) diagnostics->warn("dns.truncated", "DNS message marked truncated", 2);
    return msg;
}

PacketMetadata decode_packet_payload(Timestamp timestamp, ByteView bytes, std::size_t original_length, std::uint32_t link_type, Diagnostics* diagnostics) {
    PacketMetadata md;
    md.timestamp = timestamp;
    md.original_length = original_length;
    md.captured_length = bytes.size();
    if (link_type != 1) { md.notes.push_back("unsupported link type " + std::to_string(link_type)); return md; }
    auto eth = parse_ethernet(bytes, diagnostics);
    if (!eth) { md.notes.push_back(eth.status().message); return md; }
    md.ethernet = eth.value();
    if (md.ethernet->ether_type != 0x0800) return md;
    auto ip_bytes = bytes.slice(md.ethernet->header_length, bytes.size() - md.ethernet->header_length);
    if (!ip_bytes) return md;
    auto ip = parse_ipv4_packet(ip_bytes.value(), diagnostics);
    if (!ip) { md.notes.push_back(ip.status().message); return md; }
    md.ipv4 = ip.value();
    auto transport = ip_bytes.value().slice(md.ipv4->header_length, md.ipv4->payload_length);
    if (!transport) return md;
    if (md.ipv4->protocol == 6) {
        auto tcp = parse_tcp_segment(transport.value(), diagnostics);
        if (tcp) md.tcp = tcp.value(); else md.notes.push_back(tcp.status().message);
    } else if (md.ipv4->protocol == 17) {
        auto udp = parse_udp_datagram(transport.value(), diagnostics);
        if (udp) {
            md.udp = udp.value();
            const auto& datagram = udp.value();
            if (datagram.source_port == 53 || datagram.destination_port == 53) {
                auto dns_payload = transport.value().slice(8, datagram.payload_length);
                if (dns_payload) { auto dns = parse_dns_message(dns_payload.value(), diagnostics); if (dns) md.dns = dns.value(); else md.notes.push_back(dns.status().message); }
            }
        } else md.notes.push_back(udp.status().message);
    }
    return md;
}
core::Result<PcapFile> parse_pcap(ByteView bytes) {
    PcapFile pcap;
    Diagnostics diag;
    if (bytes.size() < 24) return Status::failure("pcap file too short");
    std::uint32_t magic_be = read_be32(bytes.data());
    std::uint32_t magic_le = read_le32(bytes.data());
    bool le = false, ns = false;
    if (magic_le == 0xa1b2c3d4u) { le = true; ns = false; }
    else if (magic_be == 0xa1b2c3d4u) { le = false; ns = false; }
    else if (magic_le == 0xa1b23c4du) { le = true; ns = true; }
    else if (magic_be == 0xa1b23c4du) { le = false; ns = true; }
    else return Status::failure("unsupported pcap magic");
    auto rd16 = [&](std::size_t off){ return le ? read_le16(bytes.data() + off) : read_be16(bytes.data() + off); };
    auto rd32 = [&](std::size_t off){ return le ? read_le32(bytes.data() + off) : read_be32(bytes.data() + off); };
    pcap.little_endian = le;
    pcap.nanosecond_resolution = ns;
    pcap.major = rd16(4);
    pcap.minor = rd16(6);
    pcap.this_zone = static_cast<std::int32_t>(rd32(8));
    pcap.snaplen = rd32(16);
    pcap.link_type = rd32(20);
    if (pcap.major != 2) diag.warn("pcap.version", "PCAP major version is unusual", 4);
    std::size_t offset = 24;
    while (offset < bytes.size()) {
        if (bytes.size() - offset < 16) { diag.warn("pcap.record", "Trailing bytes after final packet header", offset); break; }
        std::uint32_t ts_sec = rd32(offset), ts_frac = rd32(offset + 4), incl_len = rd32(offset + 8), orig_len = rd32(offset + 12);
        offset += 16;
        if (incl_len > bytes.size() - offset) { diag.error("pcap.packet", "Captured packet length exceeds file", offset); break; }
        auto pkt_bytes = bytes.slice(offset, incl_len);
        Timestamp ts = normalize_timestamp(ts_sec, ns ? ts_frac : static_cast<std::int64_t>(ts_frac) * 1000LL);
        PcapPacket pkt;
        pkt.metadata = decode_packet_payload(ts, pkt_bytes.value(), orig_len, pcap.link_type, &diag);
        pkt.payload = pkt_bytes.value().to_vector();
        pcap.packets.push_back(std::move(pkt));
        offset += incl_len;
    }
    pcap.diagnostics = std::move(diag);
    return pcap;
}
core::Result<PcapFile> parse_pcap_file(const std::string& path) {
    auto data = read_file_bytes(path);
    return parse_pcap(ByteView(data));
}
std::string ether_type_name(std::uint16_t ether_type) {
    switch (ether_type) { case 0x0800: return "IPv4"; case 0x0806: return "ARP"; case 0x86dd: return "IPv6"; case 0x8100: return "802.1Q"; default: return "0x" + bytes_to_hex(reinterpret_cast<const std::uint8_t*>(&ether_type), sizeof(ether_type)); }
}
std::string ip_protocol_name(std::uint8_t protocol) {
    switch (protocol) { case 1: return "icmp"; case 6: return "tcp"; case 17: return "udp"; case 47: return "gre"; case 50: return "esp"; case 51: return "ah"; default: return std::to_string(protocol); }
}
std::string dns_type_name(std::uint16_t type) {
    switch (type) { case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 6: return "SOA"; case 12: return "PTR"; case 15: return "MX"; case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV"; case 65: return "HTTPS"; default: return std::to_string(type); }
}
std::string service_name(std::uint16_t port, const std::string& protocol) {
    static const std::map<std::string, std::map<std::uint16_t, std::string>> services = {
        {"tcp", {{20,"ftp-data"},{21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},{80,"http"},{110,"pop3"},{143,"imap"},{389,"ldap"},{443,"https"},{445,"smb"},{465,"smtps"},{587,"smtp-client"},{993,"imaps"},{995,"pop3s"},{1433,"mssql"},{1521,"oracle"},{3306,"mysql"},{3389,"rdp"},{5432,"postgres"},{5900,"vnc"},{6379,"redis"},{8080,"http-alt"}}},
        {"udp", {{53,"dns"},{67,"dhcp-server"},{68,"dhcp-client"},{69,"tftp"},{123,"ntp"},{137,"netbios-ns"},{161,"snmp"},{500,"isakmp"},{514,"syslog"},{1900,"ssdp"},{4500,"ipsec-nat"},{5353,"mdns"}}}
    };
    auto p = services.find(protocol);
    if (p == services.end()) return {};
    auto v = p->second.find(port);
    return v == p->second.end() ? std::string{} : v->second;
}
std::string summarize_packet(const PacketMetadata& md) {
    std::ostringstream out;
    out << md.timestamp.to_string() << " len=" << md.captured_length;
    if (md.ipv4) out << " " << md.flow_key();
    if (md.dns) { out << " dns="; bool first = true; for (const auto& q : md.dns->questions) { if (!first) out << ","; out << q.name << ":" << dns_type_name(q.type); first = false; } }
    if (!md.notes.empty()) { out << " notes="; for (std::size_t i = 0; i < md.notes.size(); ++i) { if (i) out << ";"; out << md.notes[i]; } }
    return out.str();
}
std::string summarize_pcap(const PcapFile& pcap) {
    std::ostringstream out;
    out << "packets=" << pcap.packets.size() << " linktype=" << pcap.link_type << " snaplen=" << pcap.snaplen << "\n";
    auto hist = protocol_histogram(pcap);
    for (const auto& kv : hist) out << kv.first << "=" << kv.second << "\n";
    for (std::size_t i = 0; i < pcap.packets.size(); ++i) out << i << " " << summarize_packet(pcap.packets[i].metadata) << "\n";
    if (!pcap.diagnostics.empty()) out << pcap.diagnostics.summary();
    return out.str();
}
std::map<std::string, std::size_t> protocol_histogram(const PcapFile& pcap) {
    std::map<std::string, std::size_t> hist;
    for (const auto& pkt : pcap.packets) {
        if (pkt.metadata.dns) hist["dns"]++;
        else if (pkt.metadata.tcp) hist["tcp"]++;
        else if (pkt.metadata.udp) hist["udp"]++;
        else if (pkt.metadata.ipv4) hist[ip_protocol_name(pkt.metadata.ipv4->protocol)]++;
        else if (pkt.metadata.ethernet) hist[ether_type_name(pkt.metadata.ethernet->ether_type)]++;
        else hist["undecoded"]++;
    }
    return hist;
}

} // namespace packetguard::packet
