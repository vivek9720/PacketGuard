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
#include "rules/rules.hpp"

namespace packetguard::policy {

enum class FirewallDialect { iptables, nftables, generic_policy, unknown };
enum class FirewallAction { accept, drop, reject, log, return_, jump, unknown };
enum class Direction { input, output, forward, prerouting, postrouting, unknown };

struct FirewallRule {
    FirewallDialect dialect = FirewallDialect::unknown;
    Direction chain = Direction::unknown;
    FirewallAction action = FirewallAction::unknown;
    std::string jump_target;
    rules::AddressExpr source;
    rules::AddressExpr destination;
    rules::PortExpr source_ports;
    rules::PortExpr destination_ports;
    rules::RuleProtocol protocol = rules::RuleProtocol::any;
    std::string interface_in;
    std::string interface_out;
    std::string state;
    std::string comment;
    std::string raw;
    std::size_t line = 0;
};

struct PolicyKV {
    std::string section;
    std::string key;
    std::string value;
    std::size_t line = 0;
};

struct PolicyFile {
    FirewallDialect dominant_dialect = FirewallDialect::unknown;
    std::vector<FirewallRule> firewall_rules;
    std::vector<PolicyKV> settings;
    core::Diagnostics diagnostics;
};

std::string dialect_name(FirewallDialect dialect);
std::string action_name(FirewallAction action);
std::string direction_name(Direction direction);
std::optional<Direction> parse_direction(const std::string& token);
std::optional<FirewallAction> parse_firewall_action(const std::string& token);
core::Result<FirewallRule> parse_iptables_rule(const std::string& line, std::size_t line_number = 0);
core::Result<FirewallRule> parse_nftables_rule(const std::string& line, std::size_t line_number = 0);
std::vector<PolicyKV> parse_ini_policy(const std::string& text, core::Diagnostics* diagnostics = nullptr);
std::vector<PolicyKV> parse_csv_policy(const std::string& text, core::Diagnostics* diagnostics = nullptr);
std::vector<PolicyKV> parse_json_like_policy(const std::string& text, core::Diagnostics* diagnostics = nullptr);
PolicyFile parse_policy_text(const std::string& text);
PolicyFile parse_policy_file(const std::string& path);
std::vector<std::string> validate_firewall_rule(const FirewallRule& rule);
std::string normalize_firewall_rule(const FirewallRule& rule);
std::vector<std::string> duplicate_rules(const PolicyFile& file);
std::vector<std::string> shadowed_rules(const PolicyFile& file);
std::vector<std::string> ordering_warnings(const PolicyFile& file);
std::string summarize_policy(const PolicyFile& file);
bool firewall_rule_matches_tuple(const FirewallRule& rule, core::IPv4Address src, core::IPv4Address dst, std::uint16_t sport, std::uint16_t dport, rules::RuleProtocol protocol, Direction chain);

} // namespace packetguard::policy
