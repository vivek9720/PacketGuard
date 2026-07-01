#include "policy/policy.hpp"
#include <exception>
#include <iostream>
#include <string>

static void usage() { std::cout << "usage: policyaudit <policy-file> [--normalize]\n"; }
int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    bool normalize = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--normalize") normalize = true;
        else { usage(); return 2; }
    }
    try {
        auto file = packetguard::policy::parse_policy_file(argv[1]);
        std::cout << packetguard::policy::summarize_policy(file);
        if (normalize) for (const auto& rule : file.firewall_rules) std::cout << packetguard::policy::normalize_firewall_rule(rule) << "\n";
    } catch (const std::exception& e) { std::cerr << e.what() << "\n"; return 1; }
    return 0;
}
