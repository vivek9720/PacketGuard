#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace packetguard::core {

struct ServiceProfile {
    std::uint16_t port = 0;
    const char* transport = "";
    const char* service = "";
    const char* category = "";
    const char* exposure = "";
    const char* risk = "";
};

struct DnsTypeProfile {
    std::uint16_t type = 0;
    const char* mnemonic = "";
    const char* category = "";
    const char* meaning = "";
    const char* signal = "";
};

struct RuleOptionProfile {
    const char* name = "";
    const char* category = "";
    const char* value_model = "";
    const char* review_note = "";
};

struct PolicySettingProfile {
    const char* key = "";
    const char* category = "";
    const char* expected_shape = "";
    const char* review_note = "";
};

std::optional<ServiceProfile> lookup_service_profile(std::uint16_t port, const std::string& transport);
std::vector<ServiceProfile> service_profiles_by_risk(const std::string& risk);
std::vector<ServiceProfile> service_profiles_by_category(const std::string& category);
std::optional<DnsTypeProfile> lookup_dns_type_profile(std::uint16_t type);
std::optional<RuleOptionProfile> lookup_rule_option_profile(const std::string& name);
std::optional<PolicySettingProfile> lookup_policy_setting_profile(const std::string& key);
std::vector<RuleOptionProfile> known_rule_options();
std::vector<PolicySettingProfile> known_policy_settings();
std::string service_exposure_label(std::uint16_t port, const std::string& transport);
std::string dns_type_signal_label(std::uint16_t type);

} // namespace packetguard::core
