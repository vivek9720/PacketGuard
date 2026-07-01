#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include "core/diagnostics.hpp"
#include "core/ip.hpp"
#include "core/result.hpp"
#include "packet/packet.hpp"

namespace packetguard::ioc {

enum class IocType { ip, cidr, domain, url, hash, unknown };
enum class ListRole { indicator, allow, block };

struct Indicator {
    IocType type = IocType::unknown;
    ListRole role = ListRole::indicator;
    std::string raw;
    std::string normalized;
    std::string source;
    std::string severity = "medium";
    double confidence = 0.5;
    std::optional<core::IPv4Address> ip;
    std::optional<core::CIDRRange> cidr;
    std::map<std::string, std::string> attributes;
};

struct IndicatorSet {
    std::vector<Indicator> indicators;
    std::vector<Indicator> duplicates;
    core::Diagnostics diagnostics;
};

struct MatchResult {
    Indicator indicator;
    std::string field;
    std::string value;
    std::string reason;
};

std::string type_name(IocType type);
std::string role_name(ListRole role);
std::optional<IocType> infer_ioc_type(const std::string& value);
std::optional<ListRole> parse_role(const std::string& value);
std::string normalize_domain(const std::string& domain);
std::string normalize_url(const std::string& url);
std::string normalize_hash(const std::string& value);
std::string registrable_domain_hint(const std::string& domain);
bool is_valid_domain(const std::string& domain);
bool domain_matches(const std::string& indicator_domain, const std::string& observed_domain);
bool hash_length_is_known(const std::string& hash);
core::Result<Indicator> parse_indicator_line(const std::string& line, std::size_t line_number = 0);
IndicatorSet parse_indicator_text(const std::string& text, const std::string& source = {});
IndicatorSet parse_indicator_file(const std::string& path);
std::vector<MatchResult> match_packet(const IndicatorSet& set, const packet::PacketMetadata& metadata);
std::vector<MatchResult> match_packets(const IndicatorSet& set, const std::vector<packet::PcapPacket>& packets);
std::string summarize_indicators(const IndicatorSet& set);
std::string summarize_matches(const std::vector<MatchResult>& matches);
IndicatorSet merge_indicator_sets(const std::vector<IndicatorSet>& sets);

} // namespace packetguard::ioc
