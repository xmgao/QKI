#include "packet/registeripsecsapacket.hpp"

RegisterIPSECSAPacket::RegisterIPSECSAPacket()
    : registeripsecsa_source_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      registeripsecsa_destination_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      registeripsecsa_spi_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      is_inbound_ptr_(reinterpret_cast<bool *>(buffer_ + BASE_HEADER_SIZE + 3 * sizeof(uint32_t))) {}

RegisterIPSECSAPacket::RegisterIPSECSAPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      registeripsecsa_source_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      registeripsecsa_destination_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      registeripsecsa_spi_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      is_inbound_ptr_(reinterpret_cast<bool *>(buffer_ + BASE_HEADER_SIZE + 3 * sizeof(uint32_t))) {}

RegisterIPSECSAPacket::RegisterIPSECSAPacket(const RegisterIPSECSAPacket &other)
    : PacketBase(other),
      registeripsecsa_source_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      registeripsecsa_destination_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      registeripsecsa_spi_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      is_inbound_ptr_(reinterpret_cast<bool *>(buffer_ + BASE_HEADER_SIZE + 3 * sizeof(uint32_t))) {}

RegisterIPSECSAPacket::RegisterIPSECSAPacket(RegisterIPSECSAPacket &&other) noexcept = default;

uint32_t *RegisterIPSECSAPacket::getsourcePtr()
{
    return registeripsecsa_source_ptr_;
}

uint32_t *RegisterIPSECSAPacket::getdesPtr()
{
    return registeripsecsa_destination_ptr_;
}

uint32_t *RegisterIPSECSAPacket::getspiPtr()
{
    return registeripsecsa_spi_ptr_;
}

bool *RegisterIPSECSAPacket::getinboundPtr()
{
    return is_inbound_ptr_;
}

void RegisterIPSECSAPacket::ConstructRegisterIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi, bool is_inbound)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::REGISTERIPSECSA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = REGISTERIPSECSA_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIPSECSA_HEADER_SIZE);
    *this->registeripsecsa_source_ptr_ = sourceip_;
    *this->registeripsecsa_destination_ptr_ = desip_;
    *this->registeripsecsa_spi_ptr_ = spi;
    *this->is_inbound_ptr_ = is_inbound;
}

void RegisterIPSECSAPacket::ConstructDestoryIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi_id, bool is_inbound)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::DESTORYIPSECSA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = REGISTERIPSECSA_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIPSECSA_HEADER_SIZE);
    *this->registeripsecsa_source_ptr_ = sourceip_;
    *this->registeripsecsa_destination_ptr_ = desip_;
    *this->registeripsecsa_spi_ptr_ = spi_id;
    *this->is_inbound_ptr_ = is_inbound;
}
