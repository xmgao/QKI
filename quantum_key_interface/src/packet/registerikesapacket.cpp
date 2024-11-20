#include "packet/registerikesapacket.hpp"

RegisterIKESAPacket::RegisterIKESAPacket()
    : registerikesahdr_ptr(reinterpret_cast<registerikesahdr *>(buffer_ + BASE_HEADER_SIZE)) {}

RegisterIKESAPacket::RegisterIKESAPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      registerikesahdr_ptr(reinterpret_cast<registerikesahdr *>(buffer_ + BASE_HEADER_SIZE)) {}

RegisterIKESAPacket::RegisterIKESAPacket(const RegisterIKESAPacket &other)
    : PacketBase(other),
      registerikesahdr_ptr(reinterpret_cast<registerikesahdr *>(buffer_ + BASE_HEADER_SIZE)) {}

RegisterIKESAPacket::RegisterIKESAPacket(RegisterIKESAPacket &&other) noexcept = default;

registerikesahdr *RegisterIKESAPacket::getRegisterIKESAPacketHeaderPtr()
{
    return registerikesahdr_ptr;
}

void RegisterIKESAPacket::ConstructRegisterIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::REGISTERIKESA);
    header_->packet_length = REGISTERIKESA_HEADER_SIZE;
    registerikesahdr_ptr->registerikesa_source = sourceip_;
    registerikesahdr_ptr->registerikesa_destination = desip_;
    registerikesahdr_ptr->registerikesa_spiI = spi_i;
    registerikesahdr_ptr->registerikesa_spiR = spi_r;
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIKESA_HEADER_SIZE);
}

void RegisterIKESAPacket::ConstructDestoryIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::DESTORYIKESA);
    header_->packet_length = REGISTERIKESA_HEADER_SIZE;
    registerikesahdr_ptr->registerikesa_source = sourceip_;
    registerikesahdr_ptr->registerikesa_destination = desip_;
    registerikesahdr_ptr->registerikesa_spiI = spi_i;
    registerikesahdr_ptr->registerikesa_spiR = spi_r;
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIKESA_HEADER_SIZE);
}
