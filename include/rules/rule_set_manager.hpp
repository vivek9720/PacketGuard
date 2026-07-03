#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "core/diagnostics.hpp"
#include "packet/packet.hpp"
#include "rules/rules.hpp"

namespace packetguard::rules {

struct RuleMatch {
    std::size_t index = 0;
    std::uint32_t sid = 0;
    std::uint32_t rev = 0;
    std::string message;
};

struct RuleSetSnapshot {
    std::vector<SignatureRule> rules;
    std::map<std::uint32_t, std::vector<std::size_t>> sid_index;
    std::map<std::string, std::vector<std::size_t>> classtype_index;
    std::vector<std::string> warnings;
    std::uint64_t generation = 0;
};

class RuleSetManager {
public:
    RuleSetManager() = default;

    std::size_t size() const { return rules_.size(); }
    bool empty() const { return rules_.empty(); }
    std::uint64_t generation() const { return generation_; }

    bool add_rule(const SignatureRule& rule);
    bool add_rule_text(const std::string& line);
    std::size_t add_rule_file_text(const std::string& text);
    bool replace_rule(std::size_t index, const SignatureRule& rule);
    bool replace_rule_text(std::size_t index, const std::string& line);
    bool erase_index(std::size_t index);
    std::size_t erase_sid(std::uint32_t sid);
    void clear();
    void rebuild_indexes();

    std::optional<SignatureRule> find_latest_sid(std::uint32_t sid) const;
    std::vector<SignatureRule> find_by_classtype(const std::string& classtype) const;
    std::vector<RuleMatch> match_packet(const packet::PacketMetadata& metadata) const;
    RuleSetSnapshot snapshot() const;
    std::string summary() const;
    const core::Diagnostics& diagnostics() const { return diagnostics_; }

private:
    void note_validation(const SignatureRule& rule);
    void touch();

    std::vector<SignatureRule> rules_;
    std::map<std::uint32_t, std::vector<std::size_t>> sid_index_;
    std::map<std::string, std::vector<std::size_t>> classtype_index_;
    core::Diagnostics diagnostics_;
    std::uint64_t generation_ = 0;
};

} // namespace packetguard::rules
