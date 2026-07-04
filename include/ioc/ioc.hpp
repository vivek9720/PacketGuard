#pragma once
#include <cstddef>
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

struct IndexedIndicator {
    std::uint64_t id = 0;
    std::uint32_t generation = 0;
    bool active = true;
    Indicator indicator;
};

struct IocIndexStats {
    std::size_t total_records = 0;
    std::size_t active_records = 0;
    std::size_t inactive_records = 0;
    std::size_t cidr_nodes = 0;
    std::size_t domain_keys = 0;
    std::size_t hash_keys = 0;
    std::uint32_t generation = 0;
};

class IndicatorIndex {
public:
    std::uint64_t add(Indicator indicator);
    std::size_t add_set(const IndicatorSet& set);
    bool remove_id(std::uint64_t id);
    bool remove_key(const std::string& key);
    bool reactivate_id(std::uint64_t id);
    bool update_role(std::uint64_t id, ListRole role);
    bool contains_key(const std::string& key) const;
    std::vector<MatchResult> lookup_ip(core::IPv4Address ip, const std::string& field = "ip") const;
    std::vector<MatchResult> lookup_domain(const std::string& domain, const std::string& field = "domain") const;
    std::vector<MatchResult> lookup_hash(const std::string& hash, const std::string& field = "hash") const;
    std::vector<MatchResult> match_packet(const packet::PacketMetadata& metadata) const;
    void rebuild();
    void compact();
    bool validate_integrity(core::Diagnostics* diagnostics = nullptr) const;
    IocIndexStats stats() const;
    const std::vector<IndexedIndicator>& records() const { return records_; }
private:
    struct CidrTrieNode {
        int child[2] = {-1, -1};
        std::vector<std::size_t> records;
    };

    std::uint64_t next_id_ = 1;
    std::uint32_t generation_ = 1;
    std::vector<IndexedIndicator> records_;
    std::map<std::uint64_t, std::size_t> id_to_slot_;
    std::map<std::string, std::size_t> key_to_slot_;
    std::map<std::string, std::vector<std::size_t>> domains_;
    std::map<std::string, std::vector<std::size_t>> hashes_;
    std::vector<CidrTrieNode> cidr_trie_;

    void rebuild_indexes();
    void index_record(std::size_t slot);
};

class IndicatorRefreshSession {
public:
    std::size_t ingest_snapshot(const std::string& text, const std::string& source = {});
    std::size_t replace_snapshot(const std::string& text, const std::string& source = {});
    std::vector<MatchResult> match_cached_cidr(core::IPv4Address ip, const std::string& field = "ip") const;
    std::vector<MatchResult> match_packet(const packet::PacketMetadata& metadata) const;
    const IndicatorSet& current_set() const { return current_set_; }
    const IndicatorIndex& index() const { return index_; }
    IocIndexStats stats() const;
private:
    IndicatorSet current_set_;
    IndicatorIndex index_;
    std::uint32_t refresh_generation_ = 0;
};

std::string type_name(IocType type);
std::string role_name(ListRole role);
std::string indicator_key(const Indicator& indicator);
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
