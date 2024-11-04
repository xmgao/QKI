#include "registerikesapacket.hpp"

RegisterIKESAPacket::RegisterIKESAPacket()
    : registerikesa_source_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      registerikesa_destination_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      registerikesa_spiI_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      registerikesa_spiR_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t) + sizeof(uint64_t))) {}

RegisterIKESAPacket::RegisterIKESAPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      registerikesa_source_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      registerikesa_destination_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      registerikesa_spiI_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      registerikesa_spiR_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t) + sizeof(uint64_t))) {}

RegisterIKESAPacket::RegisterIKESAPacket(const RegisterIKESAPacket &other)
    : PacketBase(other),
      registerikesa_source_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      registerikesa_destination_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      registerikesa_spiI_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      registerikesa_spiR_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t) + sizeof(uint64_t))) {}

RegisterIKESAPacket::RegisterIKESAPacket(RegisterIKESAPacket &&other) noexcept = default;

uint32_t *RegisterIKESAPacket::getsourcePtr()
{
    return registerikesa_source_ptr_;
}

uint32_t *RegisterIKESAPacket::getdesPtr()
{
    return registerikesa_destination_ptr_;
}

uint64_t *RegisterIKESAPacket::getspiIPtr()
{
    return registerikesa_spiI_ptr_;
}

uint64_t *RegisterIKESAPacket::getspiRPtr()
{
    return registerikesa_spiR_ptr_;
}

void RegisterIKESAPacket::ConstructRegisterIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::REGISTERIKESA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = REGISTERIKESA_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIKESA_HEADER_SIZE);
    *this->registerikesa_source_ptr_ = sourceip_;
    *this->registerikesa_destination_ptr_ = desip_;
    *this->registerikesa_spiI_ptr_ = spi_i;
    *this->registerikesa_spiR_ptr_ = spi_r;
}

void RegisterIKESAPacket::ConstructDestoryIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::DESTORYIKESA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = REGISTERIKESA_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + REGISTERIKESA_HEADER_SIZE);
    *this->registerikesa_source_ptr_ = sourceip_;
    *this->registerikesa_destination_ptr_ = desip_;
    *this->registerikesa_spiI_ptr_ = spi_i;
    *this->registerikesa_spiR_ptr_ = spi_r;
}
