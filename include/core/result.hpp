#pragma once
#include <string>
#include <utility>

namespace packetguard::core {

enum class Severity { info, warning, error };

struct Status {
    bool ok = true;
    std::string message;
    Severity severity = Severity::info;

    static Status success() { return {}; }
    static Status warn(std::string msg) { return {true, std::move(msg), Severity::warning}; }
    static Status failure(std::string msg) { return {false, std::move(msg), Severity::error}; }
    explicit operator bool() const { return ok; }
};

template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)), status_(Status::success()), has_value_(true) {}
    Result(Status status) : status_(std::move(status)), has_value_(false) {}
    bool ok() const { return has_value_ && status_.ok; }
    explicit operator bool() const { return ok(); }
    const T& value() const { return value_; }
    T& value() { return value_; }
    const Status& status() const { return status_; }
private:
    T value_{};
    Status status_;
    bool has_value_ = false;
};

} // namespace packetguard::core
