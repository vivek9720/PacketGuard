#include "rules/rule_set_manager.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <sstream>

namespace packetguard::rules {

void RuleSetManager::touch() {
    ++generation_;
    rebuild_indexes();
}

void RuleSetManager::note_validation(const SignatureRule& rule) {
    for (const auto& warning : validate_rule(rule)) {
        diagnostics_.warn("ruleset.validate", warning, rule.line);
    }
}

bool RuleSetManager::add_rule(const SignatureRule& rule) {
    rules_.push_back(rule);
    note_validation(rules_.back());
    touch();
    return true;
}

bool RuleSetManager::add_rule_text(const std::string& line) {
    auto parsed = parse_rule_line(line, rules_.size() + 1);
    if (!parsed) {
        diagnostics_.warn("ruleset.parse", parsed.status().message, rules_.size() + 1);
        return false;
    }
    return add_rule(parsed.value());
}

std::size_t RuleSetManager::add_rule_file_text(const std::string& text) {
    auto parsed = parse_rule_text(text);
    std::size_t before = rules_.size();
    for (const auto& diagnostic : parsed.diagnostics.entries()) {
        diagnostics_.add(diagnostic.severity, diagnostic.code, diagnostic.message, diagnostic.offset);
    }
    for (const auto& rule : parsed.rules) {
        rules_.push_back(rule);
        note_validation(rules_.back());
    }
    if (rules_.size() != before) touch();
    return rules_.size() - before;
}

bool RuleSetManager::replace_rule(std::size_t index, const SignatureRule& rule) {
    if (index >= rules_.size()) {
        diagnostics_.warn("ruleset.replace", "replace index outside rule set", index);
        return false;
    }
    rules_[index] = rule;
    note_validation(rules_[index]);
    touch();
    return true;
}

bool RuleSetManager::replace_rule_text(std::size_t index, const std::string& line) {
    auto parsed = parse_rule_line(line, index + 1);
    if (!parsed) {
        diagnostics_.warn("ruleset.replace_parse", parsed.status().message, index);
        return false;
    }
    return replace_rule(index, parsed.value());
}

bool RuleSetManager::erase_index(std::size_t index) {
    if (index >= rules_.size()) {
        diagnostics_.warn("ruleset.erase", "erase index outside rule set", index);
        return false;
    }
    rules_.erase(rules_.begin() + static_cast<std::ptrdiff_t>(index));
    touch();
    return true;
}

std::size_t RuleSetManager::erase_sid(std::uint32_t sid) {
    auto old_size = rules_.size();
    rules_.erase(std::remove_if(rules_.begin(), rules_.end(), [sid](const SignatureRule& rule) {
        return rule.sid == sid;
    }), rules_.end());
    auto removed = old_size - rules_.size();
    if (removed) touch();
    return removed;
}

void RuleSetManager::clear() {
    if (rules_.empty()) return;
    rules_.clear();
    touch();
}

void RuleSetManager::rebuild_indexes() {
    sid_index_.clear();
    classtype_index_.clear();
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const auto& rule = rules_[i];
        if (rule.sid != 0) sid_index_[rule.sid].push_back(i);
        if (!rule.classtype.empty()) classtype_index_[core::to_lower(rule.classtype)].push_back(i);
    }
}

std::optional<SignatureRule> RuleSetManager::find_latest_sid(std::uint32_t sid) const {
    auto it = sid_index_.find(sid);
    if (it == sid_index_.end() || it->second.empty()) return std::nullopt;
    const SignatureRule* latest = nullptr;
    for (auto index : it->second) {
        if (index >= rules_.size()) continue;
        if (!latest || rules_[index].rev >= latest->rev) latest = &rules_[index];
    }
    if (!latest) return std::nullopt;
    return *latest;
}

std::vector<SignatureRule> RuleSetManager::find_by_classtype(const std::string& classtype) const {
    std::vector<SignatureRule> out;
    auto it = classtype_index_.find(core::to_lower(classtype));
    if (it == classtype_index_.end()) return out;
    for (auto index : it->second) {
        if (index < rules_.size()) out.push_back(rules_[index]);
    }
    return out;
}

std::vector<RuleMatch> RuleSetManager::match_packet(const packet::PacketMetadata& metadata) const {
    std::vector<RuleMatch> out;
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const auto& rule = rules_[i];
        if (rule_matches_packet(rule, metadata)) {
            out.push_back({i, rule.sid, rule.rev, rule.msg});
        }
    }
    return out;
}

RuleSetSnapshot RuleSetManager::snapshot() const {
    RuleSetSnapshot snapshot;
    snapshot.rules = rules_;
    snapshot.sid_index = sid_index_;
    snapshot.classtype_index = classtype_index_;
    snapshot.generation = generation_;
    for (const auto& diagnostic : diagnostics_.entries()) {
        snapshot.warnings.push_back(diagnostic.code + ":" + diagnostic.message);
    }
    return snapshot;
}

std::string RuleSetManager::summary() const {
    std::ostringstream out;
    out << "ruleset_rules=" << rules_.size() << "\n";
    out << "ruleset_generation=" << generation_ << "\n";
    out << "ruleset_sids=" << sid_index_.size() << "\n";
    out << "ruleset_classtypes=" << classtype_index_.size() << "\n";
    for (const auto& kv : sid_index_) {
        auto latest = find_latest_sid(kv.first);
        out << "sid." << kv.first << ".count=" << kv.second.size();
        if (latest) out << " latest_rev=" << latest->rev;
        out << "\n";
    }
    if (!diagnostics_.empty()) out << diagnostics_.summary();
    return out.str();
}

} // namespace packetguard::rules
