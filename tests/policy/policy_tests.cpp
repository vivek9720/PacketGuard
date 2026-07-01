#include "policy/policy.hpp"
#include <cstdlib>
#include <iostream>
#include <string>

static void require_policy(bool value, const std::string& message) {
    if (!value) { std::cerr << "test failed: " << message << "\n"; std::exit(1); }
}

void run_policy_tests() {
    using namespace packetguard::policy;
    auto rule = parse_iptables_rule("iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT --comment ssh-admin", 1);
    require_policy(rule.ok(), "iptables rule parses");
    require_policy(rule.value().chain == Direction::input, "chain parsed");
    require_policy(rule.value().destination_ports.matches(22), "port parsed");
    auto nft = parse_nftables_rule("add rule inet filter input ip saddr 10.0.0.0/8 tcp dport 443 accept", 2);
    require_policy(nft.ok(), "nftables rule parses");
    auto file = parse_policy_text("iptables -A INPUT -j DROP\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\n");
    require_policy(file.firewall_rules.size() == 2, "policy parses two firewall rules");
    require_policy(!ordering_warnings(file).empty(), "broad deny order warning");
    auto ini = parse_policy_text("[auth]\nminimum_password_length=14\n");
    require_policy(!ini.settings.empty(), "INI policy parsed");
}
