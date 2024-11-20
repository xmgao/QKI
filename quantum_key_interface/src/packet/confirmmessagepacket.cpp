#include "packet/confirmmessagepacket.hpp"
#include <iostream>
#include <string>

ConfirmMessagePacket::ConfirmMessagePacket()
    : error_type_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)) {}

ConfirmMessagePacket::ConfirmMessagePacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      error_type_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)) {}

ConfirmMessagePacket::ConfirmMessagePacket(const ConfirmMessagePacket &other)
    : PacketBase(other),
      error_type_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)) {}

ConfirmMessagePacket::ConfirmMessagePacket(ConfirmMessagePacket &&other) noexcept = default;

uint32_t *ConfirmMessagePacket::geterrortypePtr()
{
    return error_type_ptr_;
}

void ConfirmMessagePacket::constructConfirmMessagePacket(uint32_t errortype)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::CONFIRMMESSAGE);
    header_->packet_length = CONFIRMMESSAGE_HEADER_SIZE;
    this->setBufferSize(BASE_HEADER_SIZE + CONFIRMMESSAGE_HEADER_SIZE);
    *this->error_type_ptr_ = errortype;
}