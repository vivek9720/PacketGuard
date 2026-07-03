#include "rules/rules.hpp"
#include "rules/rule_set_manager.hpp"
#include <cstdlib>
#include <iostream>
#include <string>

static void require_rules(bool value, const std::string& message) {
    if (!value) { std::cerr << "test failed: " << message << "\n"; std::exit(1); }
}

void run_rules_tests() {
    using namespace packetguard::rules;
    auto rule = parse_rule_line("alert tcp any any -> 192.168.1.0/24 80 (msg:\"web hit\"; content:\"example\"; sid:1001; rev:1; classtype:web-application-activity;)", 1);
    require_rules(rule.ok(), "IDS rule parses");
    require_rules(rule.value().sid == 1001 && rule.value().rev == 1, "sid and rev parse");
    auto warnings = validate_rule(rule.value());
    require_rules(warnings.empty(), "valid rule has no warnings");
    auto file = parse_rule_text(rule.value().raw + "\n" + rule.value().raw + "\n");
    require_rules(file.rules.size() == 2, "rule file parses two rules");
    require_rules(!file.diagnostics.empty(), "duplicate rule diagnostic");
    auto bad = parse_rule_line("alert tcp any any", 2);
    require_rules(!bad.ok(), "bad rule rejected");
    auto bad_port = parse_rule_line("alert tcp any abc -> any 80 (msg:\"bad port\"; sid:1002; rev:1;)", 3);
    require_rules(!bad_port.ok(), "alphabetic source port rejected without throwing");
    auto bad_range = parse_rule_line("alert tcp any 1:abc -> any 80 (msg:\"bad range\"; sid:1003; rev:1;)", 4);
    require_rules(!bad_range.ok(), "alphabetic port range rejected without throwing");

    RuleSetManager manager;
    require_rules(manager.add_rule_text("alert tcp any any -> any 80 (msg:\"managed web\"; sid:2001; rev:1; classtype:web-application-activity;)"), "manager adds rule text");
    require_rules(manager.replace_rule_text(0, "alert tcp any any -> any 443 (msg:\"managed tls\"; sid:2001; rev:2; classtype:web-application-activity;)"), "manager replaces rule text");
    require_rules(manager.find_latest_sid(2001).has_value(), "manager finds latest sid");
    require_rules(manager.snapshot().generation == manager.generation(), "manager snapshot generation");

    packetguard::packet::PacketMetadata md;
    md.ipv4 = packetguard::packet::IPv4Packet{};
    auto src = packetguard::core::parse_ipv4("10.0.0.5");
    auto dst = packetguard::core::parse_ipv4("203.0.113.9");
    if (src && dst) { md.ipv4->source = *src; md.ipv4->destination = *dst; }
    md.tcp = packetguard::packet::TcpSegment{};
    md.tcp->source_port = 51000;
    md.tcp->destination_port = 443;
    require_rules(manager.match_packet(md).size() == 1, "manager matches packet metadata");
}
