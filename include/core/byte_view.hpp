#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "core/result.hpp"

namespace packetguard::core {

class ByteView {
public:
    ByteView() = default;
    ByteView(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}
    explicit ByteView(const std::vector<std::uint8_t>& data) : data_(data.data()), size_(data.size()) {}
    const std::uint8_t* data() const { return data_; }
    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }
    Result<std::uint8_t> at(std::size_t offset) const;
    Result<ByteView> slice(std::size_t offset, std::size_t length) const;
    std::vector<std::uint8_t> to_vector() const;
    std::string ascii_lossy() const;
private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

class ByteReader {
public:
    explicit ByteReader(ByteView view) : view_(view) {}
    std::size_t offset() const { return offset_; }
    std::size_t remaining() const { return offset_ <= view_.size() ? view_.size() - offset_ : 0; }
    bool can_read(std::size_t count) const { return count <= remaining(); }
    Result<std::uint8_t> read_u8();
    Result<std::uint16_t> read_be16();
    Result<std::uint32_t> read_be32();
    Result<std::uint16_t> read_le16();
    Result<std::uint32_t> read_le32();
    Result<ByteView> read_bytes(std::size_t count);
    Result<ByteView> peek_bytes(std::size_t count) const;
    void advance(std::size_t count);
private:
    ByteView view_;
    std::size_t offset_ = 0;
};

std::vector<std::uint8_t> read_file_bytes(const std::string& path, std::size_t max_bytes = 64 * 1024 * 1024);

} // namespace packetguard::core
