#include "core/byte_view.hpp"
#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace packetguard::core {

Result<std::uint8_t> ByteView::at(std::size_t offset) const {
    if (!data_ && size_ != 0) return Status::failure("invalid byte view");
    if (offset >= size_) return Status::failure("byte offset outside view");
    return data_[offset];
}
Result<ByteView> ByteView::slice(std::size_t offset, std::size_t length) const {
    if (!data_ && size_ != 0) return Status::failure("invalid byte view");
    if (offset > size_ || length > size_ - offset) return Status::failure("slice outside view");
    if (length == 0) return ByteView(data_, 0);
    return ByteView(data_ + offset, length);
}
std::vector<std::uint8_t> ByteView::to_vector() const {
    if (!data_ || size_ == 0) return {};
    return std::vector<std::uint8_t>(data_, data_ + size_);
}
std::string ByteView::ascii_lossy() const {
    std::string s;
    if (!data_ && size_ != 0) return s;
    s.reserve(size_);
    for (std::size_t i = 0; i < size_; ++i) {
        const auto c = data_[i];
        s.push_back(c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
    }
    return s;
}
Result<std::uint8_t> ByteReader::read_u8() {
    if (!can_read(1)) return Status::failure("short read for u8");
    return view_.data()[offset_++];
}
Result<std::uint16_t> ByteReader::read_be16() {
    if (!can_read(2)) return Status::failure("short read for be16");
    auto v = static_cast<std::uint16_t>((view_.data()[offset_] << 8) | view_.data()[offset_ + 1]);
    offset_ += 2;
    return v;
}
Result<std::uint32_t> ByteReader::read_be32() {
    if (!can_read(4)) return Status::failure("short read for be32");
    std::uint32_t v = (static_cast<std::uint32_t>(view_.data()[offset_]) << 24) |
                      (static_cast<std::uint32_t>(view_.data()[offset_ + 1]) << 16) |
                      (static_cast<std::uint32_t>(view_.data()[offset_ + 2]) << 8) |
                      static_cast<std::uint32_t>(view_.data()[offset_ + 3]);
    offset_ += 4;
    return v;
}
Result<std::uint16_t> ByteReader::read_le16() {
    if (!can_read(2)) return Status::failure("short read for le16");
    auto v = static_cast<std::uint16_t>(view_.data()[offset_] | (view_.data()[offset_ + 1] << 8));
    offset_ += 2;
    return v;
}
Result<std::uint32_t> ByteReader::read_le32() {
    if (!can_read(4)) return Status::failure("short read for le32");
    std::uint32_t v = static_cast<std::uint32_t>(view_.data()[offset_]) |
                      (static_cast<std::uint32_t>(view_.data()[offset_ + 1]) << 8) |
                      (static_cast<std::uint32_t>(view_.data()[offset_ + 2]) << 16) |
                      (static_cast<std::uint32_t>(view_.data()[offset_ + 3]) << 24);
    offset_ += 4;
    return v;
}
Result<ByteView> ByteReader::read_bytes(std::size_t count) {
    if (!can_read(count)) return Status::failure("short read for byte span");
    auto res = view_.slice(offset_, count);
    if (res) offset_ += count;
    return res;
}
Result<ByteView> ByteReader::peek_bytes(std::size_t count) const {
    if (!can_read(count)) return Status::failure("short peek for byte span");
    return view_.slice(offset_, count);
}
void ByteReader::advance(std::size_t count) { offset_ = std::min(view_.size(), offset_ + count); }

std::vector<std::uint8_t> read_file_bytes(const std::string& path, std::size_t max_bytes) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("unable to open file: " + path);
    in.seekg(0, std::ios::end);
    auto end = in.tellg();
    if (end < 0) throw std::runtime_error("unable to size file: " + path);
    auto size = static_cast<std::size_t>(end);
    if (size > max_bytes) throw std::runtime_error("file exceeds maximum supported size: " + path);
    in.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(size);
    if (size && !in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size))) throw std::runtime_error("unable to read file: " + path);
    return bytes;
}

} // namespace packetguard::core
