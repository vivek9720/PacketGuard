#include "core/strings.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace packetguard::core {

std::string to_lower(std::string value) { std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); }); return value; }
std::string to_upper(std::string value) { std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); }); return value; }
std::string trim(std::string value) {
    auto b = std::find_if_not(value.begin(), value.end(), [](unsigned char c){ return std::isspace(c); });
    auto e = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c){ return std::isspace(c); }).base();
    if (b >= e) return {};
    return std::string(b, e);
}
std::vector<std::string> split(const std::string& value, char delim, bool keep_empty) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream in(value);
    while (std::getline(in, cur, delim)) if (keep_empty || !cur.empty()) out.push_back(cur);
    if (keep_empty && !value.empty() && value.back() == delim) out.push_back({});
    return out;
}
std::vector<std::string> split_ws(const std::string& value) {
    std::istringstream in(value);
    std::vector<std::string> out;
    std::string token;
    while (in >> token) out.push_back(token);
    return out;
}
bool starts_with(const std::string& value, const std::string& prefix) { return value.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), value.begin()); }
bool ends_with(const std::string& value, const std::string& suffix) { return value.size() >= suffix.size() && std::equal(suffix.rbegin(), suffix.rend(), value.rbegin()); }
bool iequals(const std::string& a, const std::string& b) { return to_lower(a) == to_lower(b); }
bool contains_ci(const std::string& haystack, const std::string& needle) { return to_lower(haystack).find(to_lower(needle)) != std::string::npos; }
std::string collapse_spaces(const std::string& value) {
    std::string out;
    bool prev = false;
    for (unsigned char c : value) {
        if (std::isspace(c)) { if (!prev) out.push_back(' '); prev = true; }
        else { out.push_back(static_cast<char>(c)); prev = false; }
    }
    return trim(out);
}
std::string strip_quotes(std::string value) {
    value = trim(std::move(value));
    if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') || (value.front() == '\'' && value.back() == '\''))) return value.substr(1, value.size() - 2);
    return value;
}
bool is_hex_string(const std::string& value) {
    if (value.empty()) return false;
    for (unsigned char c : value) if (!std::isxdigit(c)) return false;
    return true;
}
bool is_decimal(const std::string& value) {
    if (value.empty()) return false;
    for (unsigned char c : value) if (!std::isdigit(c)) return false;
    return true;
}
std::string bytes_to_hex(const std::uint8_t* data, std::size_t size) {
    static const char* lut = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) { out.push_back(lut[data[i] >> 4]); out.push_back(lut[data[i] & 15]); }
    return out;
}
std::vector<std::uint8_t> hex_to_bytes(const std::string& hex) {
    std::string h;
    for (unsigned char c : hex) if (!std::isspace(c) && c != ':' && c != '-') h.push_back(static_cast<char>(c));
    if (h.size() % 2 != 0 || !is_hex_string(h)) return {};
    std::vector<std::uint8_t> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2) out.push_back(static_cast<std::uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}
std::string remove_comment(const std::string& line) {
    bool in_quote = false;
    char quote = 0;
    for (std::size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if ((c == '"' || c == '\'') && (i == 0 || line[i - 1] != '\\')) { if (!in_quote) { in_quote = true; quote = c; } else if (quote == c) in_quote = false; }
        if (!in_quote && c == '#') return line.substr(0, i);
        if (!in_quote && c == '/' && i + 1 < line.size() && line[i + 1] == '/') return line.substr(0, i);
    }
    return line;
}
std::vector<std::string> read_text_lines(const std::string& path, std::size_t max_bytes) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("unable to open file: " + path);
    in.seekg(0, std::ios::end);
    auto size = static_cast<std::size_t>(in.tellg());
    if (size > max_bytes) throw std::runtime_error("text file exceeds maximum supported size: " + path);
    in.seekg(0, std::ios::beg);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

} // namespace packetguard::core
