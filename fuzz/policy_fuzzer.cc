#include "policy/policy.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    auto file = packetguard::policy::parse_policy_text(text);
    (void)packetguard::policy::summarize_policy(file);
    auto src = packetguard::core::parse_ipv4("10.0.0.5");
    auto dst = packetguard::core::parse_ipv4("203.0.113.10");
    if (src && dst) {
        for (const auto& rule : file.firewall_rules) {
            (void)packetguard::policy::validate_firewall_rule(rule);
            (void)packetguard::policy::normalize_firewall_rule(rule);
            (void)packetguard::policy::firewall_rule_matches_tuple(rule, *src, *dst, 53000, 443, packetguard::rules::RuleProtocol::tcp, packetguard::policy::Direction::output);
        }
    }
    return 0;
}
