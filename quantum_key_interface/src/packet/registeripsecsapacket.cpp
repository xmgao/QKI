#include "packet/registeripsecsapacket.hpp"

RegisterIPSECSAPacket::RegisterIPSECSAPacket()
    : registeripsecsa_header_ptr(reinterpret_cast<registeripsecsahdr *>(buffer_ + BASE_HEADER_SIZE)) {}

RegisterIPSECSAPacket::RegisterIPSECSAPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      registeripsecsa_header_ptr(reinterpret_cast<registeripsecsahdr *>(buffer_ + BASE_HEADER_SIZE)) {}
RegisterIPSECSAPacket::RegisterIPSECSAPacket(const RegisterIPSECSAPacket &other)
    : PacketBase(other),
      registeripsecsa_header_ptr(reinterpret_cast<registeripsecsahdr *>(buffer_ + BASE_HEADER_SIZE)) {}

RegisterIPSECSAPacket::RegisterIPSECSAPacket(RegisterIPSECSAPacket &&other) noexcept = default;

registeripsecsahdr *RegisterIPSECSAPacket::getRegisterIPSECSAPacketHeader()
{
    return registeripsecsa_header_ptr;
}

void RegisterIPSECSAPacket::ConstructRegisterIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi, bool is_inbound)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::REGISTERIPSECSA);
    header_->packet_length = REGISTERIPSECSA_HEADER_SIZE;
    registeripsecsa_header_ptr->registeripsecsa_source = sourceip_;
    registeripsecsa_header_ptr->registeripsecsa_destination = desip_;
    registeripsecsa_header_ptr->registeripsecsa_spi = spi;
    registeripsecsa_header_ptr->is_inbound = is_inbound;
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIPSECSA_HEADER_SIZE);
}

void RegisterIPSECSAPacket::ConstructDestoryIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi, bool is_inbound)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::DESTORYIPSECSA);
    header_->packet_length = REGISTERIPSECSA_HEADER_SIZE;
    registeripsecsa_header_ptr->registeripsecsa_source = sourceip_;
    registeripsecsa_header_ptr->registeripsecsa_destination = desip_;
    registeripsecsa_header_ptr->registeripsecsa_spi = spi;
    registeripsecsa_header_ptr->is_inbound = is_inbound;
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIPSECSA_HEADER_SIZE);
}
