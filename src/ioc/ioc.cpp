#include "ioc/ioc.hpp"
#include "core/strings.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace packetguard::ioc {
using namespace packetguard::core;

std::string type_name(IocType type) {
    switch (type) { case IocType::ip: return "ip"; case IocType::cidr: return "cidr"; case IocType::domain: return "domain"; case IocType::url: return "url"; case IocType::hash: return "hash"; default: return "unknown"; }
}
std::string role_name(ListRole role) {
    switch (role) { case ListRole::allow: return "allow"; case ListRole::block: return "block"; default: return "indicator"; }
}
std::optional<ListRole> parse_role(const std::string& value) {
    auto v = to_lower(trim(value));
    if (v == "allow" || v == "allowlist" || v == "whitelist") return ListRole::allow;
    if (v == "block" || v == "blocklist" || v == "deny" || v == "denylist") return ListRole::block;
    if (v == "indicator" || v == "ioc" || v == "detect") return ListRole::indicator;
    return std::nullopt;
}
static std::string strip_trailing_dot(std::string v) { while (!v.empty() && v.back() == '.') v.pop_back(); return v; }
std::string normalize_domain(const std::string& domain) {
    auto v = to_lower(strip_trailing_dot(trim(domain)));
    if (starts_with(v, "*.")) v = v.substr(2);
    if (starts_with(v, ".")) v = v.substr(1);
    return v;
}
bool is_valid_domain(const std::string& domain) {
    auto d = normalize_domain(domain);
    if (d.empty() || d.size() > 253 || d.find('.') == std::string::npos) return false;
    auto labels = split(d, '.', true);
    for (const auto& label : labels) {
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (unsigned char c : label) if (!std::isalnum(c) && c != '-') return false;
    }
    return true;
}
std::string normalize_url(const std::string& url) {
    auto v = trim(url);
    auto scheme_pos = v.find("://");
    std::string scheme;
    if (scheme_pos != std::string::npos) { scheme = to_lower(v.substr(0, scheme_pos)); v = v.substr(scheme_pos + 3); } else scheme = "http";
    auto slash = v.find('/');
    std::string host = slash == std::string::npos ? v : v.substr(0, slash);
    std::string path = slash == std::string::npos ? "/" : v.substr(slash);
    auto at = host.rfind('@');
    if (at != std::string::npos) host = host.substr(at + 1);
    std::string port;
    auto colon = host.rfind(':');
    if (colon != std::string::npos && host.find(']') == std::string::npos) { port = host.substr(colon + 1); host = host.substr(0, colon); }
    host = normalize_domain(host);
    if ((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) port.clear();
    while (path.find("//") != std::string::npos) path = std::regex_replace(path, std::regex("//+"), "/");
    return scheme + "://" + host + (port.empty() ? "" : ":" + port) + path;
}
std::string normalize_hash(const std::string& value) {
    auto v = to_lower(trim(value));
    auto colon = v.find(':');
    if (colon != std::string::npos) v = v.substr(colon + 1);
    std::string out;
    for (unsigned char c : v) if (std::isxdigit(c)) out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}
bool hash_length_is_known(const std::string& hash) {
    auto len = normalize_hash(hash).size();
    return len == 32 || len == 40 || len == 56 || len == 64 || len == 96 || len == 128;
}
std::string registrable_domain_hint(const std::string& domain) {
    auto parts = split(normalize_domain(domain), '.', false);
    if (parts.size() <= 2) return normalize_domain(domain);
    static const std::set<std::string> compound = {"co.uk","org.uk","com.au","net.au","co.jp","com.br","com.mx","co.in"};
    std::string last2 = parts[parts.size() - 2] + "." + parts.back();
    if (compound.count(last2) && parts.size() >= 3) return parts[parts.size() - 3] + "." + last2;
    return last2;
}
bool domain_matches(const std::string& indicator_domain, const std::string& observed_domain) {
    auto ind = normalize_domain(indicator_domain);
    auto obs = normalize_domain(observed_domain);
    if (ind.empty() || obs.empty()) return false;
    return obs == ind || ends_with(obs, "." + ind);
}
std::optional<IocType> infer_ioc_type(const std::string& value) {
    auto v = trim(value);
    if (v.empty()) return std::nullopt;
    if (parse_cidr(v)) return v.find('/') == std::string::npos ? IocType::ip : IocType::cidr;
    auto h = normalize_hash(v);
    if (h.size() >= 32 && is_hex_string(h) && hash_length_is_known(h)) return IocType::hash;
    auto low = to_lower(v);
    if (starts_with(low, "http://") || starts_with(low, "https://")) return IocType::url;
    if (is_valid_domain(v) || (starts_with(v, "*.") && is_valid_domain(v.substr(2)))) return IocType::domain;
    return std::nullopt;
}
static std::map<std::string, std::string> parse_attributes(const std::vector<std::string>& fields, std::size_t start) {
    std::map<std::string, std::string> attrs;
    for (std::size_t i = start; i < fields.size(); ++i) {
        auto f = trim(fields[i]);
        auto eq = f.find('=');
        if (eq == std::string::npos) continue;
        attrs[to_lower(trim(f.substr(0, eq)))] = strip_quotes(trim(f.substr(eq + 1)));
    }
    return attrs;
}
core::Result<Indicator> parse_indicator_line(const std::string& line, std::size_t line_number) {
    auto clean = trim(remove_comment(line));
    if (clean.empty()) return Status::failure("empty indicator line");
    char delim = clean.find(',') != std::string::npos ? ',' : clean.find('|') != std::string::npos ? '|' : ' ';
    auto fields = delim == ' ' ? split_ws(clean) : split(clean, delim, false);
    if (fields.empty()) return Status::failure("no indicator fields");
    Indicator ind;
    ind.raw = clean;
    std::size_t value_index = 0;
    auto maybe_type = infer_ioc_type(fields[0]);
    std::string type_token = to_lower(trim(fields[0]));
    if (!maybe_type && fields.size() > 1) {
        if (type_token == "ip") { ind.type = IocType::ip; value_index = 1; }
        else if (type_token == "cidr") { ind.type = IocType::cidr; value_index = 1; }
        else if (type_token == "domain" || type_token == "host") { ind.type = IocType::domain; value_index = 1; }
        else if (type_token == "url") { ind.type = IocType::url; value_index = 1; }
        else if (type_token == "hash" || type_token == "md5" || type_token == "sha1" || type_token == "sha256") { ind.type = IocType::hash; value_index = 1; }
    }
    if (ind.type == IocType::unknown) {
        maybe_type = infer_ioc_type(fields[value_index]);
        if (!maybe_type) return Status::failure("unrecognized indicator on line " + std::to_string(line_number));
        ind.type = *maybe_type;
    }
    auto value = strip_quotes(trim(fields[value_index]));
    if (fields.size() > value_index + 1) {
        if (auto role = parse_role(fields[value_index + 1])) ind.role = *role;
    }
    ind.attributes = parse_attributes(fields, value_index + 1);
    if (ind.attributes.count("severity")) ind.severity = to_lower(ind.attributes["severity"]);
    if (ind.attributes.count("confidence")) {
        try { ind.confidence = std::max(0.0, std::min(1.0, std::stod(ind.attributes["confidence"]))); } catch (...) {}
    }
    switch (ind.type) {
        case IocType::ip: {
            auto ip = parse_ipv4(value);
            if (!ip) return Status::failure("invalid IPv4 indicator");
            ind.ip = ip; ind.normalized = ipv4_to_string(*ip); break;
        }
        case IocType::cidr: {
            auto cidr = parse_cidr(value);
            if (!cidr) return Status::failure("invalid CIDR indicator");
            ind.cidr = cidr; ind.normalized = cidr->to_string(); break;
        }
        case IocType::domain: {
            if (!is_valid_domain(value) && !(starts_with(value, "*.") && is_valid_domain(value.substr(2)))) return Status::failure("invalid domain indicator");
            ind.normalized = normalize_domain(value); break;
        }
        case IocType::url: ind.normalized = normalize_url(value); break;
        case IocType::hash: {
            ind.normalized = normalize_hash(value);
            if (!hash_length_is_known(ind.normalized)) return Status::failure("hash length is not recognized");
            break;
        }
        default: return Status::failure("unknown indicator type");
    }
    return ind;
}
IndicatorSet parse_indicator_text(const std::string& text, const std::string& source) {
    IndicatorSet set;
    std::istringstream in(text);
    std::string line;
    std::set<std::string> seen;
    std::size_t line_no = 0;
    while (std::getline(in, line)) {
        line_no++;
        auto clean = trim(remove_comment(line));
        if (clean.empty()) continue;
        auto parsed = parse_indicator_line(line, line_no);
        if (!parsed) { set.diagnostics.warn("ioc.parse", parsed.status().message, line_no); continue; }
        auto ind = parsed.value();
        ind.source = source;
        auto key = type_name(ind.type) + ":" + role_name(ind.role) + ":" + ind.normalized;
        if (!seen.insert(key).second) { set.duplicates.push_back(ind); set.diagnostics.info("ioc.duplicate", "duplicate indicator " + ind.normalized, line_no); continue; }
        set.indicators.push_back(std::move(ind));
    }
    return set;
}
IndicatorSet parse_indicator_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("unable to open IOC file: " + path);
    std::ostringstream buf; buf << in.rdbuf();
    return parse_indicator_text(buf.str(), path);
}
static void maybe_add_ip_matches(const IndicatorSet& set, IPv4Address ip, const std::string& field, std::vector<MatchResult>& out) {
    auto s = ipv4_to_string(ip);
    for (const auto& ind : set.indicators) {
        if (ind.type == IocType::ip && ind.ip && ind.ip->value == ip.value) out.push_back({ind, field, s, "exact IPv4 match"});
        if (ind.type == IocType::cidr && ind.cidr && ind.cidr->contains(ip)) out.push_back({ind, field, s, "CIDR containment match"});
    }
}
static void maybe_add_domain_matches(const IndicatorSet& set, const std::string& domain, std::vector<MatchResult>& out) {
    for (const auto& ind : set.indicators) {
        if (ind.type == IocType::domain && domain_matches(ind.normalized, domain)) out.push_back({ind, "dns.name", normalize_domain(domain), "domain suffix match"});
        if (ind.type == IocType::url) {
            auto n = ind.normalized;
            auto scheme = n.find("://");
            auto rest = scheme == std::string::npos ? n : n.substr(scheme + 3);
            auto slash = rest.find('/');
            auto host = slash == std::string::npos ? rest : rest.substr(0, slash);
            if (domain_matches(host, domain)) out.push_back({ind, "dns.name", normalize_domain(domain), "URL host match"});
        }
    }
}
std::vector<MatchResult> match_packet(const IndicatorSet& set, const packet::PacketMetadata& metadata) {
    std::vector<MatchResult> out;
    if (metadata.ipv4) {
        maybe_add_ip_matches(set, metadata.ipv4->source, "ipv4.source", out);
        maybe_add_ip_matches(set, metadata.ipv4->destination, "ipv4.destination", out);
    }
    for (const auto& name : metadata.domain_names()) maybe_add_domain_matches(set, name, out);
    std::vector<MatchResult> filtered;
    for (const auto& m : out) {
        bool allowed = false;
        for (const auto& allow : out) if (allow.indicator.role == ListRole::allow && allow.field == m.field && allow.value == m.value) { allowed = true; break; }
        if (!allowed || m.indicator.role == ListRole::allow) filtered.push_back(m);
    }
    return filtered;
}
std::vector<MatchResult> match_packets(const IndicatorSet& set, const std::vector<packet::PcapPacket>& packets) {
    std::vector<MatchResult> out;
    for (const auto& pkt : packets) {
        auto matches = match_packet(set, pkt.metadata);
        out.insert(out.end(), matches.begin(), matches.end());
    }
    return out;
}
std::string summarize_indicators(const IndicatorSet& set) {
    std::map<std::string, std::size_t> by_type, by_role;
    for (const auto& ind : set.indicators) { by_type[type_name(ind.type)]++; by_role[role_name(ind.role)]++; }
    std::ostringstream out;
    out << "indicators=" << set.indicators.size() << " duplicates=" << set.duplicates.size() << "\n";
    for (const auto& kv : by_type) out << "type." << kv.first << "=" << kv.second << "\n";
    for (const auto& kv : by_role) out << "role." << kv.first << "=" << kv.second << "\n";
    if (!set.diagnostics.empty()) out << set.diagnostics.summary();
    return out.str();
}
std::string summarize_matches(const std::vector<MatchResult>& matches) {
    std::ostringstream out;
    out << "matches=" << matches.size() << "\n";
    for (const auto& m : matches) out << m.field << "=" << m.value << " indicator=" << type_name(m.indicator.type) << ":" << m.indicator.normalized << " role=" << role_name(m.indicator.role) << " severity=" << m.indicator.severity << " confidence=" << m.indicator.confidence << " reason=" << m.reason << "\n";
    return out.str();
}
IndicatorSet merge_indicator_sets(const std::vector<IndicatorSet>& sets) {
    IndicatorSet merged;
    std::set<std::string> seen;
    for (const auto& set : sets) {
        for (auto d : set.diagnostics.entries()) merged.diagnostics.add(d.severity, d.code, d.message, d.offset);
        for (const auto& ind : set.indicators) {
            auto key = type_name(ind.type) + ":" + role_name(ind.role) + ":" + ind.normalized;
            if (!seen.insert(key).second) { merged.duplicates.push_back(ind); continue; }
            merged.indicators.push_back(ind);
        }
    }
    return merged;
}

} // namespace packetguard::ioc
