#include "rules/rules.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace packetguard::rules {
using namespace packetguard::core;

std::string action_name(RuleAction action) {
    switch (action) { case RuleAction::alert: return "alert"; case RuleAction::pass: return "pass"; case RuleAction::drop: return "drop"; case RuleAction::reject: return "reject"; case RuleAction::log: return "log"; default: return "unknown"; }
}
std::string protocol_name(RuleProtocol protocol) {
    switch (protocol) { case RuleProtocol::tcp: return "tcp"; case RuleProtocol::udp: return "udp"; case RuleProtocol::icmp: return "icmp"; case RuleProtocol::ip: return "ip"; case RuleProtocol::dns: return "dns"; case RuleProtocol::http: return "http"; case RuleProtocol::any: return "any"; default: return "unknown"; }
}
std::optional<RuleAction> parse_action(const std::string& token) {
    auto v = to_lower(token);
    if (v == "alert") return RuleAction::alert;
    if (v == "pass") return RuleAction::pass;
    if (v == "drop") return RuleAction::drop;
    if (v == "reject") return RuleAction::reject;
    if (v == "log") return RuleAction::log;
    return std::nullopt;
}
std::optional<RuleProtocol> parse_protocol(const std::string& token) {
    auto v = to_lower(token);
    if (v == "tcp") return RuleProtocol::tcp;
    if (v == "udp") return RuleProtocol::udp;
    if (v == "icmp") return RuleProtocol::icmp;
    if (v == "ip") return RuleProtocol::ip;
    if (v == "dns") return RuleProtocol::dns;
    if (v == "http") return RuleProtocol::http;
    if (v == "any") return RuleProtocol::any;
    return std::nullopt;
}
bool PortExpr::matches(std::uint16_t port) const {
    bool hit = any;
    if (!any) {
        hit = false;
        for (const auto& r : ranges) if (port >= r.first && port <= r.second) { hit = true; break; }
    }
    return negated ? !hit : hit;
}
std::string PortExpr::to_string() const {
    if (any && !negated) return "any";
    std::ostringstream out;
    if (negated) out << "!";
    for (std::size_t i = 0; i < ranges.size(); ++i) {
        if (i) out << ",";
        out << ranges[i].first;
        if (ranges[i].second != ranges[i].first) out << ":" << ranges[i].second;
    }
    return out.str();
}
static core::Result<std::pair<std::uint16_t, std::uint16_t>> parse_port_range(const std::string& token) {
    auto t = trim(token);
    auto parse_port_number = [](const std::string& value) -> core::Result<std::uint16_t> {
        if (!is_decimal(value)) return Status::failure("invalid port");
        unsigned int parsed = 0;
        for (char c : value) {
            parsed = parsed * 10u + static_cast<unsigned int>(c - '0');
            if (parsed > 65535u) return Status::failure("port outside range");
        }
        return static_cast<std::uint16_t>(parsed);
    };
    auto colon = t.find(':');
    if (colon == std::string::npos) {
        auto p = parse_port_number(t);
        if (!p) return p.status();
        return std::make_pair(p.value(), p.value());
    }
    auto left = t.substr(0, colon), right = t.substr(colon + 1);
    auto lo = left.empty() ? core::Result<std::uint16_t>(static_cast<std::uint16_t>(0)) : parse_port_number(left);
    auto hi = right.empty() ? core::Result<std::uint16_t>(static_cast<std::uint16_t>(65535)) : parse_port_number(right);
    if (!lo) return lo.status();
    if (!hi) return hi.status();
    if (lo.value() > hi.value()) return Status::failure("invalid port range");
    return std::make_pair(lo.value(), hi.value());
}
core::Result<PortExpr> parse_port_expr(const std::string& token) {
    PortExpr expr;
    auto t = trim(token);
    if (t.empty()) return Status::failure("empty port expression");
    if (t.front() == '!') { expr.negated = true; t = trim(t.substr(1)); }
    if (t == "any") return expr;
    expr.any = false;
    if (t.front() == '[' && t.back() == ']') t = t.substr(1, t.size() - 2);
    for (const auto& part : split(t, ',', false)) {
        auto r = parse_port_range(part);
        if (!r) return r.status();
        expr.ranges.push_back(r.value());
    }
    return expr;
}
bool AddressExpr::matches(core::IPv4Address address) const {
    bool hit = any;
    if (!any) {
        hit = false;
        for (const auto& range : ranges) if (range.contains(address)) { hit = true; break; }
    }
    return negated ? !hit : hit;
}
std::string AddressExpr::to_string() const {
    if (any && !negated) return "any";
    std::ostringstream out;
    if (negated) out << "!";
    bool first = true;
    for (const auto& r : ranges) { if (!first) out << ","; out << r.to_string(); first = false; }
    for (const auto& v : variables) { if (!first) out << ","; out << v; first = false; }
    return out.str();
}
core::Result<AddressExpr> parse_address_expr(const std::string& token) {
    AddressExpr expr;
    auto t = trim(token);
    if (t.empty()) return Status::failure("empty address expression");
    if (t.front() == '!') { expr.negated = true; t = trim(t.substr(1)); }
    if (t == "any") return expr;
    expr.any = false;
    if (t.front() == '[' && t.back() == ']') t = t.substr(1, t.size() - 2);
    for (auto part : split(t, ',', false)) {
        part = trim(part);
        if (part.empty()) continue;
        if (!part.empty() && part.front() == '$') { expr.variables.push_back(part); continue; }
        auto cidr = parse_cidr(part);
        if (!cidr) return Status::failure("invalid address expression: " + part);
        expr.ranges.push_back(*cidr);
    }
    return expr;
}
static std::vector<std::string> split_option_body(const std::string& body) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quote = false;
    bool escaped = false;
    for (char c : body) {
        if (escaped) { cur.push_back(c); escaped = false; continue; }
        if (c == '\\') { cur.push_back(c); escaped = true; continue; }
        if (c == '"') { in_quote = !in_quote; cur.push_back(c); continue; }
        if (c == ';' && !in_quote) { if (!trim(cur).empty()) out.push_back(trim(cur)); cur.clear(); continue; }
        cur.push_back(c);
    }
    if (!trim(cur).empty()) out.push_back(trim(cur));
    return out;
}
std::vector<RuleOption> parse_options(const std::string& body, Diagnostics* diagnostics, std::size_t line) {
    std::vector<RuleOption> options;
    for (const auto& part : split_option_body(body)) {
        auto colon = part.find(':');
        RuleOption opt;
        if (colon == std::string::npos) { opt.key = to_lower(trim(part)); opt.value = "true"; }
        else { opt.key = to_lower(trim(part.substr(0, colon))); opt.value = strip_quotes(trim(part.substr(colon + 1))); }
        if (opt.key.empty() && diagnostics) diagnostics->warn("rule.option", "empty rule option", line);
        else options.push_back(opt);
    }
    return options;
}
static std::optional<std::string> option_value(const SignatureRule& rule, const std::string& key) {
    for (const auto& opt : rule.options) if (opt.key == key) return opt.value;
    return std::nullopt;
}
static std::optional<std::uint32_t> parse_u32_option(const std::string& value) {
    if (!is_decimal(value)) return std::nullopt;
    std::uint64_t parsed = 0;
    for (char c : value) {
        parsed = parsed * 10u + static_cast<unsigned int>(c - '0');
        if (parsed > 0xffffffffull) return std::nullopt;
    }
    return static_cast<std::uint32_t>(parsed);
}
core::Result<SignatureRule> parse_rule_line(const std::string& line, std::size_t line_number) {
    auto clean = trim(remove_comment(line));
    if (clean.empty()) return Status::failure("empty rule line");
    auto open = clean.find('(');
    auto close = clean.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close < open) return Status::failure("rule missing option block");
    auto header = collapse_spaces(clean.substr(0, open));
    auto body = clean.substr(open + 1, close - open - 1);
    auto tokens = split_ws(header);
    if (tokens.size() != 7) return Status::failure("rule header must have seven fields");
    SignatureRule rule;
    rule.raw = clean;
    rule.line = line_number;
    auto action = parse_action(tokens[0]); if (!action) return Status::failure("unknown rule action"); rule.action = *action;
    auto proto = parse_protocol(tokens[1]); if (!proto) return Status::failure("unknown rule protocol"); rule.protocol = *proto;
    auto src = parse_address_expr(tokens[2]); if (!src) return src.status(); rule.source = src.value();
    auto sp = parse_port_expr(tokens[3]); if (!sp) return sp.status(); rule.source_ports = sp.value();
    if (tokens[4] != "->" && tokens[4] != "<>") return Status::failure("unsupported rule direction");
    rule.direction = tokens[4];
    auto dst = parse_address_expr(tokens[5]); if (!dst) return dst.status(); rule.destination = dst.value();
    auto dp = parse_port_expr(tokens[6]); if (!dp) return dp.status(); rule.destination_ports = dp.value();
    Diagnostics local;
    rule.options = parse_options(body, &local, line_number);
    if (auto v = option_value(rule, "msg")) rule.msg = *v;
    if (auto v = option_value(rule, "content")) rule.content = *v;
    if (auto v = option_value(rule, "sid")) { if (auto parsed = parse_u32_option(*v)) rule.sid = *parsed; }
    if (auto v = option_value(rule, "rev")) { if (auto parsed = parse_u32_option(*v)) rule.rev = *parsed; }
    if (auto v = option_value(rule, "classtype")) rule.classtype = *v;
    return rule;
}
RuleFile parse_rule_text(const std::string& text) {
    RuleFile file;
    std::istringstream in(text);
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(in, line)) {
        line_no++;
        auto clean = trim(remove_comment(line));
        if (clean.empty()) continue;
        auto parsed = parse_rule_line(line, line_no);
        if (!parsed) { file.diagnostics.warn("rule.parse", parsed.status().message, line_no); continue; }
        auto warnings = validate_rule(parsed.value());
        for (const auto& w : warnings) file.diagnostics.warn("rule.validate", w, line_no);
        file.rules.push_back(parsed.value());
    }
    for (const auto& d : duplicate_rule_keys(file)) file.diagnostics.warn("rule.duplicate", d, 0);
    for (const auto& s : sid_revision_conflicts(file)) file.diagnostics.warn("rule.sid", s, 0);
    return file;
}
RuleFile parse_rule_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("unable to open rule file: " + path);
    std::ostringstream buf; buf << in.rdbuf();
    return parse_rule_text(buf.str());
}
std::vector<std::string> validate_rule(const SignatureRule& rule) {
    std::vector<std::string> out;
    if (rule.action == RuleAction::unknown) out.push_back("unknown action");
    if (rule.protocol == RuleProtocol::unknown) out.push_back("unknown protocol");
    if (rule.sid == 0) out.push_back("missing sid");
    if (rule.rev == 0) out.push_back("missing rev");
    if (rule.msg.empty()) out.push_back("missing msg");
    if (rule.protocol == RuleProtocol::dns && !rule.destination_ports.matches(53) && !rule.source_ports.matches(53)) out.push_back("dns rule does not reference port 53");
    if (rule.protocol == RuleProtocol::http && !rule.destination_ports.matches(80) && !rule.destination_ports.matches(443) && !rule.source_ports.matches(80) && !rule.source_ports.matches(443)) out.push_back("http rule does not reference common web ports");
    std::set<std::string> singletons = {"sid","rev","msg","classtype","reference","metadata"};
    std::map<std::string, int> counts;
    for (const auto& opt : rule.options) counts[opt.key]++;
    for (const auto& kv : counts) if (singletons.count(kv.first) && kv.second > 1) out.push_back("option appears more than once: " + kv.first);
    return out;
}
std::string normalize_rule(const SignatureRule& rule) {
    std::ostringstream out;
    out << action_name(rule.action) << " " << protocol_name(rule.protocol) << " " << rule.source.to_string() << " " << rule.source_ports.to_string() << " " << rule.direction << " " << rule.destination.to_string() << " " << rule.destination_ports.to_string() << " (";
    std::vector<RuleOption> opts = rule.options;
    std::stable_sort(opts.begin(), opts.end(), [](const RuleOption& a, const RuleOption& b){ return a.key < b.key; });
    for (const auto& opt : opts) {
        out << opt.key;
        if (opt.value != "true") out << ":\"" << opt.value << "\"";
        out << "; ";
    }
    out << ")";
    return out.str();
}
std::string rule_key(const SignatureRule& rule) {
    return action_name(rule.action) + "|" + protocol_name(rule.protocol) + "|" + rule.source.to_string() + "|" + rule.source_ports.to_string() + "|" + rule.direction + "|" + rule.destination.to_string() + "|" + rule.destination_ports.to_string() + "|" + rule.content;
}
std::vector<std::string> duplicate_rule_keys(const RuleFile& file) {
    std::map<std::string, std::vector<std::uint32_t>> by_key;
    for (const auto& rule : file.rules) by_key[rule_key(rule)].push_back(rule.sid);
    std::vector<std::string> out;
    for (const auto& kv : by_key) if (kv.second.size() > 1) out.push_back("duplicate rule logic affects " + std::to_string(kv.second.size()) + " signatures");
    return out;
}
std::vector<std::string> sid_revision_conflicts(const RuleFile& file) {
    std::map<std::uint32_t, std::set<std::uint32_t>> sid_revs;
    for (const auto& rule : file.rules) if (rule.sid) sid_revs[rule.sid].insert(rule.rev);
    std::vector<std::string> out;
    for (const auto& kv : sid_revs) if (kv.second.size() > 1) out.push_back("sid " + std::to_string(kv.first) + " appears with multiple revisions");
    return out;
}
static bool proto_matches(RuleProtocol rule, const packet::PacketMetadata& md) {
    if (rule == RuleProtocol::any) return true;
    if (!md.ipv4) return false;
    if (rule == RuleProtocol::ip) return true;
    if (rule == RuleProtocol::tcp) return md.tcp.has_value();
    if (rule == RuleProtocol::udp) return md.udp.has_value();
    if (rule == RuleProtocol::icmp) return md.ipv4->protocol == 1;
    if (rule == RuleProtocol::dns) return md.dns.has_value();
    if (rule == RuleProtocol::http) return (md.tcp && (md.tcp->destination_port == 80 || md.tcp->destination_port == 443 || md.tcp->source_port == 80 || md.tcp->source_port == 443));
    return false;
}
bool rule_matches_packet(const SignatureRule& rule, const packet::PacketMetadata& md) {
    if (!proto_matches(rule.protocol, md)) return false;
    if (!md.ipv4) return false;
    auto forward_addr = rule.source.matches(md.ipv4->source) && rule.destination.matches(md.ipv4->destination);
    auto reverse_addr = rule.direction == "<>" && rule.source.matches(md.ipv4->destination) && rule.destination.matches(md.ipv4->source);
    std::uint16_t sp = md.tcp ? md.tcp->source_port : md.udp ? md.udp->source_port : 0;
    std::uint16_t dp = md.tcp ? md.tcp->destination_port : md.udp ? md.udp->destination_port : 0;
    auto forward_ports = rule.source_ports.matches(sp) && rule.destination_ports.matches(dp);
    auto reverse_ports = rule.direction == "<>" && rule.source_ports.matches(dp) && rule.destination_ports.matches(sp);
    if (!((forward_addr && forward_ports) || (reverse_addr && reverse_ports))) return false;
    if (!rule.content.empty()) {
        std::string needle = to_lower(rule.content);
        bool seen = false;
        for (const auto& d : md.domain_names()) if (to_lower(d).find(needle) != std::string::npos) seen = true;
        if (!seen && md.dns) for (const auto& r : md.dns->answers) if (to_lower(r.data_text).find(needle) != std::string::npos) seen = true;
        if (!seen) return false;
    }
    return true;
}
std::vector<const SignatureRule*> matching_rules(const RuleFile& file, const packet::PacketMetadata& metadata) {
    std::vector<const SignatureRule*> out;
    for (const auto& rule : file.rules) if (rule_matches_packet(rule, metadata)) out.push_back(&rule);
    return out;
}
std::string summarize_rules(const RuleFile& file) {
    std::map<std::string, std::size_t> actions, protocols, classes;
    for (const auto& rule : file.rules) { actions[action_name(rule.action)]++; protocols[protocol_name(rule.protocol)]++; if (!rule.classtype.empty()) classes[rule.classtype]++; }
    std::ostringstream out;
    out << "rules=" << file.rules.size() << "\n";
    for (const auto& kv : actions) out << "action." << kv.first << "=" << kv.second << "\n";
    for (const auto& kv : protocols) out << "protocol." << kv.first << "=" << kv.second << "\n";
    for (const auto& kv : classes) out << "classtype." << kv.first << "=" << kv.second << "\n";
    if (!file.diagnostics.empty()) out << file.diagnostics.summary();
    return out.str();
}

} // namespace packetguard::rules
