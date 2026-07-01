#pragma once
#include <cstddef>
#include <string>
#include <vector>
#include "core/result.hpp"

namespace packetguard::core {

struct Diagnostic {
    Severity severity = Severity::info;
    std::string code;
    std::string message;
    std::size_t offset = 0;
};

class Diagnostics {
public:
    void add(Severity severity, std::string code, std::string message, std::size_t offset = 0);
    void info(std::string code, std::string message, std::size_t offset = 0);
    void warn(std::string code, std::string message, std::size_t offset = 0);
    void error(std::string code, std::string message, std::size_t offset = 0);
    bool has_errors() const;
    bool empty() const { return entries_.empty(); }
    const std::vector<Diagnostic>& entries() const { return entries_; }
    std::string summary() const;
private:
    std::vector<Diagnostic> entries_;
};

} // namespace packetguard::core
