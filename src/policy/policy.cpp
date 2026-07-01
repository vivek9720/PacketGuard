#include "policy/policy.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace packetguard::policy {
using namespace packetguard::core;

std::string dialect_name(FirewallDialect dialect) {
    switch (dialect) { case FirewallDialect::iptables: return "iptables"; case FirewallDialect::nftables: return "nftables"; case FirewallDialect::generic_policy: return "generic-policy"; default: return "unknown"; }
}
std::string action_name(FirewallAction action) {
    switch (action) { case FirewallAction::accept: return "ACCEPT"; case FirewallAction::drop: return "DROP"; case FirewallAction::reject: return "REJECT"; case FirewallAction::log: return "LOG"; case FirewallAction::return_: return "RETURN"; case FirewallAction::jump: return "JUMP"; default: return "UNKNOWN"; }
}
std::string direction_name(Direction direction) {
    switch (direction) { case Direction::input: return "INPUT"; case Direction::output: return "OUTPUT"; case Direction::forward: return "FORWARD"; case Direction::prerouting: return "PREROUTING"; case Direction::postrouting: return "POSTROUTING"; default: return "UNKNOWN"; }
}
std::optional<Direction> parse_direction(const std::string& token) {
    auto v = to_upper(trim(token));
    if (v == "INPUT" || v == "IN" || v == "INPUTHOOK") return Direction::input;
    if (v == "OUTPUT" || v == "OUT" || v == "OUTPUTHOOK") return Direction::output;
    if (v == "FORWARD" || v == "FWD") return Direction::forward;
    if (v == "PREROUTING") return Direction::prerouting;
    if (v == "POSTROUTING") return Direction::postrouting;
    return std::nullopt;
}
std::optional<FirewallAction> parse_firewall_action(const std::string& token) {
    auto v = to_upper(trim(token));
    if (v == "ACCEPT" || v == "ALLOW") return FirewallAction::accept;
    if (v == "DROP" || v == "DENY") return FirewallAction::drop;
    if (v == "REJECT") return FirewallAction::reject;
    if (v == "LOG") return FirewallAction::log;
    if (v == "RETURN") return FirewallAction::return_;
    if (!v.empty()) return FirewallAction::jump;
    return std::nullopt;
}
static rules::PortExpr any_port() { return rules::PortExpr{}; }
static rules::AddressExpr any_addr() { return rules::AddressExpr{}; }
static std::string next_value(const std::vector<std::string>& t, std::size_t& i) { if (i + 1 >= t.size()) return {}; return t[++i]; }
core::Result<FirewallRule> parse_iptables_rule(const std::string& line, std::size_t line_number) {
    auto clean = trim(remove_comment(line));
    if (clean.empty()) return Status::failure("empty firewall rule");
    auto tokens = split_ws(clean);
    FirewallRule rule;
    rule.raw = clean; rule.line = line_number; rule.dialect = FirewallDialect::iptables; rule.source = any_addr(); rule.destination = any_addr(); rule.source_ports = any_port(); rule.destination_ports = any_port();
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        auto tok = tokens[i];
        if (tok == "iptables" || tok == "ip6tables") continue;
        if (tok == "-A" || tok == "--append" || tok == "-I" || tok == "--insert") { auto dir = parse_direction(next_value(tokens, i)); if (dir) rule.chain = *dir; }
        else if (tok == "-p" || tok == "--protocol") { auto p = rules::parse_protocol(next_value(tokens, i)); if (p) rule.protocol = *p; }
        else if (tok == "-s" || tok == "--source") { auto a = rules::parse_address_expr(next_value(tokens, i)); if (a) rule.source = a.value(); else return a.status(); }
        else if (tok == "-d" || tok == "--destination") { auto a = rules::parse_address_expr(next_value(tokens, i)); if (a) rule.destination = a.value(); else return a.status(); }
        else if (tok == "--sport" || tok == "--source-port" || tok == "--sports") { auto p = rules::parse_port_expr(next_value(tokens, i)); if (p) rule.source_ports = p.value(); else return p.status(); }
        else if (tok == "--dport" || tok == "--destination-port" || tok == "--dports") { auto p = rules::parse_port_expr(next_value(tokens, i)); if (p) rule.destination_ports = p.value(); else return p.status(); }
        else if (tok == "-i" || tok == "--in-interface") rule.interface_in = next_value(tokens, i);
        else if (tok == "-o" || tok == "--out-interface") rule.interface_out = next_value(tokens, i);
        else if (tok == "-m") { std::string mod = next_value(tokens, i); if (mod == "state" || mod == "conntrack") rule.state = mod; }
        else if (tok == "--state" || tok == "--ctstate") rule.state = next_value(tokens, i);
        else if (tok == "-j" || tok == "--jump") { rule.jump_target = next_value(tokens, i); auto a = parse_firewall_action(rule.jump_target); if (a) rule.action = *a; }
        else if (tok == "--comment") rule.comment = strip_quotes(next_value(tokens, i));
    }
    if (rule.chain == Direction::unknown) return Status::failure("iptables rule missing chain");
    if (rule.action == FirewallAction::unknown) return Status::failure("iptables rule missing jump action");
    return rule;
}
core::Result<FirewallRule> parse_nftables_rule(const std::string& line, std::size_t line_number) {
    auto clean = trim(remove_comment(line));
    if (clean.empty()) return Status::failure("empty nftables rule");
    auto tokens = split_ws(clean);
    FirewallRule rule;
    rule.raw = clean; rule.line = line_number; rule.dialect = FirewallDialect::nftables; rule.source = any_addr(); rule.destination = any_addr(); rule.source_ports = any_port(); rule.destination_ports = any_port();
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        auto tok = to_lower(tokens[i]);
        if (tok == "chain" && i + 1 < tokens.size()) { auto dir = parse_direction(tokens[++i]); if (dir) rule.chain = *dir; }
        else if ((tok == "hook" || tok == "type") && i + 1 < tokens.size()) { auto dir = parse_direction(tokens[i + 1]); if (dir) rule.chain = *dir; }
        else if (tok == "ip" && i + 2 < tokens.size()) {
            auto field = to_lower(tokens[++i]);
            if (field == "saddr") { auto a = rules::parse_address_expr(tokens[++i]); if (a) rule.source = a.value(); else return a.status(); }
            else if (field == "daddr") { auto a = rules::parse_address_expr(tokens[++i]); if (a) rule.destination = a.value(); else return a.status(); }
        }
        else if ((tok == "tcp" || tok == "udp") && i + 2 < tokens.size()) {
            auto proto = rules::parse_protocol(tok); if (proto) rule.protocol = *proto;
            auto field = to_lower(tokens[++i]);
            if (field == "sport") { auto p = rules::parse_port_expr(tokens[++i]); if (p) rule.source_ports = p.value(); else return p.status(); }
            else if (field == "dport") { auto p = rules::parse_port_expr(tokens[++i]); if (p) rule.destination_ports = p.value(); else return p.status(); }
        }
        else if (tok == "iif" || tok == "iifname") rule.interface_in = strip_quotes(next_value(tokens, i));
        else if (tok == "oif" || tok == "oifname") rule.interface_out = strip_quotes(next_value(tokens, i));
        else if (tok == "ct" && i + 2 < tokens.size() && to_lower(tokens[i + 1]) == "state") { i += 2; rule.state = tokens[i]; }
        else if (tok == "accept" || tok == "drop" || tok == "reject" || tok == "log" || tok == "return") { auto a = parse_firewall_action(tok); if (a) rule.action = *a; rule.jump_target = to_upper(tok); }
        else if (tok == "comment") rule.comment = strip_quotes(next_value(tokens, i));
    }
    if (rule.chain == Direction::unknown) {
        if (clean.find("input") != std::string::npos) rule.chain = Direction::input;
        else if (clean.find("output") != std::string::npos) rule.chain = Direction::output;
        else if (clean.find("forward") != std::string::npos) rule.chain = Direction::forward;
    }
    if (rule.action == FirewallAction::unknown) return Status::failure("nftables rule missing action");
    return rule;
}
std::vector<PolicyKV> parse_ini_policy(const std::string& text, Diagnostics* diagnostics) {
    std::vector<PolicyKV> out;
    std::istringstream in(text);
    std::string line, section;
    std::size_t n = 0;
    while (std::getline(in, line)) {
        n++;
        auto clean = trim(remove_comment(line));
        if (clean.empty()) continue;
        if (clean.front() == '[' && clean.back() == ']') { section = trim(clean.substr(1, clean.size() - 2)); continue; }
        auto eq = clean.find('=');
        if (eq == std::string::npos) { if (diagnostics) diagnostics->warn("policy.ini", "line lacks key/value separator", n); continue; }
        out.push_back({section, to_lower(trim(clean.substr(0, eq))), strip_quotes(trim(clean.substr(eq + 1))), n});
    }
    return out;
}
static std::vector<std::string> csv_split_line(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool quote = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') { if (quote && i + 1 < line.size() && line[i + 1] == '"') { cur.push_back('"'); i++; } else quote = !quote; }
        else if (c == ',' && !quote) { out.push_back(trim(cur)); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(trim(cur));
    return out;
}
std::vector<PolicyKV> parse_csv_policy(const std::string& text, Diagnostics* diagnostics) {
    std::vector<PolicyKV> out;
    std::istringstream in(text);
    std::string line;
    std::vector<std::string> headers;
    std::size_t n = 0;
    while (std::getline(in, line)) {
        n++;
        auto clean = trim(line);
        if (clean.empty()) continue;
        auto cols = csv_split_line(clean);
        if (headers.empty()) { for (auto& c : cols) headers.push_back(to_lower(strip_quotes(c))); continue; }
        if (cols.size() != headers.size() && diagnostics) diagnostics->warn("policy.csv", "row column count differs from header", n);
        for (std::size_t i = 0; i < cols.size() && i < headers.size(); ++i) out.push_back({"row" + std::to_string(n), headers[i], strip_quotes(cols[i]), n});
    }
    return out;
}
std::vector<PolicyKV> parse_json_like_policy(const std::string& text, Diagnostics* diagnostics) {
    std::vector<PolicyKV> out;
    std::regex pair_re("\\\"([^\\\"]+)\\\"\\s*:\\s*(\\\"([^\\\"]*)\\\"|true|false|null|-?[0-9]+)");
    auto begin = std::sregex_iterator(text.begin(), text.end(), pair_re);
    auto end = std::sregex_iterator();
    std::size_t idx = 0;
    for (auto it = begin; it != end; ++it) {
        auto key = (*it)[1].str();
        auto value = (*it)[3].matched ? (*it)[3].str() : (*it)[2].str();
        out.push_back({"json", to_lower(key), value, ++idx});
    }
    if (out.empty() && diagnostics) diagnostics->warn("policy.json", "no simple JSON properties were extracted", 0);
    return out;
}
PolicyFile parse_policy_text(const std::string& text) {
    PolicyFile file;
    std::istringstream in(text);
    std::string line;
    std::size_t n = 0;
    std::size_t ipt = 0, nft = 0;
    while (std::getline(in, line)) {
        n++;
        auto clean = trim(remove_comment(line));
        if (clean.empty()) continue;
        core::Result<FirewallRule> parsed = Status::failure("unparsed");
        if (starts_with(clean, "iptables") || clean.find(" -A ") != std::string::npos || starts_with(clean, "-A ") || starts_with(clean, "-I ")) { parsed = parse_iptables_rule(clean, n); ipt++; }
        else if (clean.find(" nft ") != std::string::npos || starts_with(clean, "add rule") || clean.find(" ip saddr ") != std::string::npos || clean.find(" tcp dport ") != std::string::npos || clean.find(" udp dport ") != std::string::npos) { parsed = parse_nftables_rule(clean, n); nft++; }
        if (parsed) {
            auto warnings = validate_firewall_rule(parsed.value());
            for (const auto& w : warnings) file.diagnostics.warn("policy.validate", w, n);
            file.firewall_rules.push_back(parsed.value());
        } else if (parsed.status().message != "unparsed") file.diagnostics.warn("policy.rule", parsed.status().message, n);
    }
    if (file.firewall_rules.empty()) {
        if (text.find('=') != std::string::npos && text.find('[') != std::string::npos) file.settings = parse_ini_policy(text, &file.diagnostics);
        else if (text.find(',') != std::string::npos && text.find('\n') != std::string::npos) file.settings = parse_csv_policy(text, &file.diagnostics);
        else if (text.find('{') != std::string::npos || text.find('"') != std::string::npos) file.settings = parse_json_like_policy(text, &file.diagnostics);
        if (!file.settings.empty()) file.dominant_dialect = FirewallDialect::generic_policy;
    } else file.dominant_dialect = ipt >= nft ? FirewallDialect::iptables : FirewallDialect::nftables;
    for (const auto& d : duplicate_rules(file)) file.diagnostics.warn("policy.duplicate", d, 0);
    for (const auto& s : shadowed_rules(file)) file.diagnostics.warn("policy.shadow", s, 0);
    for (const auto& o : ordering_warnings(file)) file.diagnostics.warn("policy.order", o, 0);
    return file;
}
PolicyFile parse_policy_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("unable to open policy file: " + path);
    std::ostringstream buf; buf << in.rdbuf();
    return parse_policy_text(buf.str());
}
std::vector<std::string> validate_firewall_rule(const FirewallRule& rule) {
    std::vector<std::string> out;
    if (rule.chain == Direction::unknown) out.push_back("rule has unknown chain");
    if (rule.action == FirewallAction::unknown) out.push_back("rule has unknown action");
    if (rule.protocol == rules::RuleProtocol::any && (!rule.source_ports.any || !rule.destination_ports.any)) out.push_back("port constraint has no explicit protocol");
    if ((rule.chain == Direction::input || rule.chain == Direction::forward) && rule.interface_out.size() && rule.interface_in.empty()) out.push_back("input-facing chain sets only output interface");
    if ((rule.chain == Direction::output) && rule.interface_in.size() && rule.interface_out.empty()) out.push_back("output chain sets only input interface");
    return out;
}
std::string normalize_firewall_rule(const FirewallRule& r) {
    std::ostringstream out;
    out << dialect_name(r.dialect) << " " << direction_name(r.chain) << " " << rules::protocol_name(r.protocol) << " " << r.source.to_string() << " " << r.source_ports.to_string() << " -> " << r.destination.to_string() << " " << r.destination_ports.to_string() << " " << action_name(r.action);
    if (!r.interface_in.empty()) out << " iif=" << r.interface_in;
    if (!r.interface_out.empty()) out << " oif=" << r.interface_out;
    if (!r.state.empty()) out << " state=" << r.state;
    return out.str();
}
std::vector<std::string> duplicate_rules(const PolicyFile& file) {
    std::map<std::string, std::vector<std::size_t>> seen;
    for (const auto& r : file.firewall_rules) seen[normalize_firewall_rule(r)].push_back(r.line);
    std::vector<std::string> out;
    for (const auto& kv : seen) if (kv.second.size() > 1) out.push_back("duplicate firewall rule at line " + std::to_string(kv.second.front()));
    return out;
}
static bool same_scope(const FirewallRule& a, const FirewallRule& b) {
    return a.chain == b.chain && a.protocol == b.protocol && a.source.to_string() == b.source.to_string() && a.destination.to_string() == b.destination.to_string() && a.source_ports.to_string() == b.source_ports.to_string() && a.destination_ports.to_string() == b.destination_ports.to_string();
}
std::vector<std::string> shadowed_rules(const PolicyFile& file) {
    std::vector<std::string> out;
    for (std::size_t i = 0; i < file.firewall_rules.size(); ++i) {
        const auto& earlier = file.firewall_rules[i];
        if (!(earlier.action == FirewallAction::accept || earlier.action == FirewallAction::drop || earlier.action == FirewallAction::reject)) continue;
        for (std::size_t j = i + 1; j < file.firewall_rules.size(); ++j) {
            const auto& later = file.firewall_rules[j];
            if (same_scope(earlier, later)) out.push_back("line " + std::to_string(later.line) + " is shadowed by line " + std::to_string(earlier.line));
        }
    }
    return out;
}
std::vector<std::string> ordering_warnings(const PolicyFile& file) {
    std::vector<std::string> out;
    std::map<Direction, bool> broad_drop_seen;
    for (const auto& r : file.firewall_rules) {
        bool broad = r.source.any && r.destination.any && r.source_ports.any && r.destination_ports.any && r.protocol == rules::RuleProtocol::any;
        if (broad_drop_seen[r.chain] && r.action == FirewallAction::accept) out.push_back("allow rule at line " + std::to_string(r.line) + " appears after a broad deny in the same chain");
        if (broad && (r.action == FirewallAction::drop || r.action == FirewallAction::reject)) broad_drop_seen[r.chain] = true;
    }
    return out;
}
bool firewall_rule_matches_tuple(const FirewallRule& r, IPv4Address src, IPv4Address dst, std::uint16_t sport, std::uint16_t dport, rules::RuleProtocol protocol, Direction chain) {
    if (r.chain != Direction::unknown && chain != Direction::unknown && r.chain != chain) return false;
    if (r.protocol != rules::RuleProtocol::any && protocol != rules::RuleProtocol::any && r.protocol != protocol) return false;
    return r.source.matches(src) && r.destination.matches(dst) && r.source_ports.matches(sport) && r.destination_ports.matches(dport);
}
std::string summarize_policy(const PolicyFile& file) {
    std::map<std::string, std::size_t> actions, chains, protocols;
    for (const auto& r : file.firewall_rules) { actions[action_name(r.action)]++; chains[direction_name(r.chain)]++; protocols[rules::protocol_name(r.protocol)]++; }
    std::ostringstream out;
    out << "dialect=" << dialect_name(file.dominant_dialect) << " firewall_rules=" << file.firewall_rules.size() << " settings=" << file.settings.size() << "\n";
    for (const auto& kv : chains) out << "chain." << kv.first << "=" << kv.second << "\n";
    for (const auto& kv : actions) out << "action." << kv.first << "=" << kv.second << "\n";
    for (const auto& kv : protocols) out << "protocol." << kv.first << "=" << kv.second << "\n";
    for (const auto& setting : file.settings) out << "setting." << setting.section << "." << setting.key << "=" << setting.value << "\n";
    if (!file.diagnostics.empty()) out << file.diagnostics.summary();
    return out.str();
}

} // namespace packetguard::policy
