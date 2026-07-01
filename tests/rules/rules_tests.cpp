#include "rules/rules.hpp"
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
}
