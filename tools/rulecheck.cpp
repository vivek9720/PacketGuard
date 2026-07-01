#include "rules/rules.hpp"
#include <exception>
#include <iostream>
#include <string>

static void usage() { std::cout << "usage: rulecheck <rule-file> [--normalize]\n"; }
int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    bool normalize = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--normalize") normalize = true;
        else { usage(); return 2; }
    }
    try {
        auto file = packetguard::rules::parse_rule_file(argv[1]);
        std::cout << packetguard::rules::summarize_rules(file);
        if (normalize) for (const auto& rule : file.rules) std::cout << packetguard::rules::normalize_rule(rule) << "\n";
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
    return 0;
}
