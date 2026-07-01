#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace packetguard::core {
struct Timestamp {
    std::int64_t seconds = 0;
    std::int32_t nanos = 0;
    std::string to_string() const;
};
std::optional<Timestamp> parse_unix_timestamp(const std::string& value);
std::optional<Timestamp> parse_iso8601_utc(const std::string& value);
Timestamp normalize_timestamp(std::int64_t seconds, std::int64_t fractional_nanos);
} // namespace packetguard::core
