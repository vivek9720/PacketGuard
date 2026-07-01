#include "core/time.hpp"
#include "core/strings.hpp"
#include <ctime>
#include <iomanip>
#include <sstream>

namespace packetguard::core {

Timestamp normalize_timestamp(std::int64_t seconds, std::int64_t fractional_nanos) {
    while (fractional_nanos >= 1000000000LL) { seconds++; fractional_nanos -= 1000000000LL; }
    while (fractional_nanos < 0) { seconds--; fractional_nanos += 1000000000LL; }
    return {seconds, static_cast<std::int32_t>(fractional_nanos)};
}
std::string Timestamp::to_string() const {
    std::time_t t = static_cast<std::time_t>(seconds);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << "." << std::setw(9) << std::setfill('0') << nanos << "Z";
    return out.str();
}
std::optional<Timestamp> parse_unix_timestamp(const std::string& value) {
    auto v = trim(value);
    auto pos = v.find('.');
    if (pos == std::string::npos) {
        if (!is_decimal(v)) return std::nullopt;
        return Timestamp{std::stoll(v), 0};
    }
    auto sec = v.substr(0, pos);
    auto frac = v.substr(pos + 1);
    if (!is_decimal(sec) || !is_decimal(frac)) return std::nullopt;
    while (frac.size() < 9) frac.push_back('0');
    if (frac.size() > 9) frac = frac.substr(0, 9);
    return Timestamp{std::stoll(sec), static_cast<std::int32_t>(std::stol(frac))};
}
std::optional<Timestamp> parse_iso8601_utc(const std::string& value) {
    if (value.size() < 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':') return std::nullopt;
    std::tm tm{};
    try {
        tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
        tm.tm_mon = std::stoi(value.substr(5, 2)) - 1;
        tm.tm_mday = std::stoi(value.substr(8, 2));
        tm.tm_hour = std::stoi(value.substr(11, 2));
        tm.tm_min = std::stoi(value.substr(14, 2));
        tm.tm_sec = std::stoi(value.substr(17, 2));
    } catch (...) { return std::nullopt; }
#if defined(_WIN32)
    auto seconds = _mkgmtime(&tm);
#else
    auto seconds = timegm(&tm);
#endif
    if (seconds < 0) return std::nullopt;
    return Timestamp{static_cast<std::int64_t>(seconds), 0};
}

} // namespace packetguard::core
