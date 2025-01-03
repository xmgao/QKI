#include "packetbase.hpp"

PacketBase::PacketBase() : buffer_size_(BASE_HEADER_SIZE)
{
    buffer_ = new uint8_t[MAX_BUFFER_SIZE]();
    header_ = reinterpret_cast<basepktheader *>(buffer_); // initialize header
}

PacketBase::PacketBase(const PacketBase &other) : buffer_size_(other.buffer_size_)
{
    buffer_ = new uint8_t[MAX_BUFFER_SIZE]();
    memcpy(buffer_, other.buffer_, buffer_size_);
    header_ = reinterpret_cast<basepktheader *>(buffer_); // initialize header
}

PacketBase::PacketBase(PacketBase &&other) noexcept : buffer_size_(other.buffer_size_)
{
    buffer_ = other.buffer_;
    other.buffer_ = nullptr;
    other.buffer_size_ = 0;
    header_ = reinterpret_cast<basepktheader *>(buffer_); // initialize header
}

PacketBase::~PacketBase()
{
    delete[] buffer_;
}

uint8_t *PacketBase::getBufferPtr()
{
    return buffer_;
}

size_t PacketBase::getBufferSize() const
{
    return buffer_size_;
}

void PacketBase::setBufferSize(size_t size)
{
    buffer_size_ = size;
}
