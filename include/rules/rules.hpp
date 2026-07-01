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

namespace packetguard::rules {

enum class RuleAction { alert, pass, drop, reject, log, unknown };
enum class RuleProtocol { tcp, udp, icmp, ip, dns, http, any, unknown };

struct PortExpr {
    bool any = true;
    bool negated = false;
    std::vector<std::pair<std::uint16_t, std::uint16_t>> ranges;
    bool matches(std::uint16_t port) const;
    std::string to_string() const;
};

struct AddressExpr {
    bool any = true;
    bool negated = false;
    std::vector<core::CIDRRange> ranges;
    std::vector<std::string> variables;
    bool matches(core::IPv4Address address) const;
    std::string to_string() const;
};

struct RuleOption {
    std::string key;
    std::string value;
};

struct SignatureRule {
    RuleAction action = RuleAction::unknown;
    RuleProtocol protocol = RuleProtocol::unknown;
    AddressExpr source;
    PortExpr source_ports;
    std::string direction = "->";
    AddressExpr destination;
    PortExpr destination_ports;
    std::vector<RuleOption> options;
    std::string msg;
    std::string content;
    std::uint32_t sid = 0;
    std::uint32_t rev = 0;
    std::string classtype;
    std::string raw;
    std::size_t line = 0;
};

struct RuleFile {
    std::vector<SignatureRule> rules;
    core::Diagnostics diagnostics;
};

std::string action_name(RuleAction action);
std::string protocol_name(RuleProtocol protocol);
std::optional<RuleAction> parse_action(const std::string& token);
std::optional<RuleProtocol> parse_protocol(const std::string& token);
core::Result<PortExpr> parse_port_expr(const std::string& token);
core::Result<AddressExpr> parse_address_expr(const std::string& token);
std::vector<RuleOption> parse_options(const std::string& body, core::Diagnostics* diagnostics = nullptr, std::size_t line = 0);
core::Result<SignatureRule> parse_rule_line(const std::string& line, std::size_t line_number = 0);
RuleFile parse_rule_text(const std::string& text);
RuleFile parse_rule_file(const std::string& path);
std::vector<std::string> validate_rule(const SignatureRule& rule);
std::string normalize_rule(const SignatureRule& rule);
std::string summarize_rules(const RuleFile& file);
bool rule_matches_packet(const SignatureRule& rule, const packet::PacketMetadata& metadata);
std::vector<const SignatureRule*> matching_rules(const RuleFile& file, const packet::PacketMetadata& metadata);
std::vector<std::string> duplicate_rule_keys(const RuleFile& file);
std::vector<std::string> sid_revision_conflicts(const RuleFile& file);
std::string rule_key(const SignatureRule& rule);

} // namespace packetguard::rules
