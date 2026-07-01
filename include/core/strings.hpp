#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace packetguard::core {
std::string to_lower(std::string value);
std::string to_upper(std::string value);
std::string trim(std::string value);
std::vector<std::string> split(const std::string& value, char delim, bool keep_empty = false);
std::vector<std::string> split_ws(const std::string& value);
bool starts_with(const std::string& value, const std::string& prefix);
bool ends_with(const std::string& value, const std::string& suffix);
bool iequals(const std::string& a, const std::string& b);
bool contains_ci(const std::string& haystack, const std::string& needle);
std::string collapse_spaces(const std::string& value);
std::string strip_quotes(std::string value);
bool is_hex_string(const std::string& value);
bool is_decimal(const std::string& value);
std::string bytes_to_hex(const std::uint8_t* data, std::size_t size);
std::vector<std::uint8_t> hex_to_bytes(const std::string& hex);
std::string remove_comment(const std::string& line);
std::vector<std::string> read_text_lines(const std::string& path, std::size_t max_bytes = 32 * 1024 * 1024);
} // namespace packetguard::core
