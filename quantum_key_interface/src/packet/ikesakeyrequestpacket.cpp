#include "packet/ikesakeyrequestpacket.hpp"

IKESAKeyRequestPacket::IKESAKeyRequestPacket()
    : keyreq_spiI_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_spiR_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint64_t))),
      keyreq_seq_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint64_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint64_t) + sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IKESAKEYREQUEST_HEADER_SIZE) {}

IKESAKeyRequestPacket::IKESAKeyRequestPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      keyreq_spiI_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_spiR_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint64_t))),
      keyreq_seq_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint64_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint64_t) + sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IKESAKEYREQUEST_HEADER_SIZE) {}

IKESAKeyRequestPacket::IKESAKeyRequestPacket(const IKESAKeyRequestPacket &other)
    : PacketBase(other),
      keyreq_spiI_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_spiR_ptr_(reinterpret_cast<uint64_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint64_t))),
      keyreq_seq_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint64_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint64_t) + sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IKESAKEYREQUEST_HEADER_SIZE) {}

IKESAKeyRequestPacket::IKESAKeyRequestPacket(IKESAKeyRequestPacket &&other) noexcept = default;

uint8_t *IKESAKeyRequestPacket::getKeyBufferPtr()
{
    return keyreq_payloadptr_;
}

uint64_t *IKESAKeyRequestPacket::getspiIPtr()
{
    return keyreq_spiI_ptr_;
}

uint64_t *IKESAKeyRequestPacket::getspiRPtr()
{
    return keyreq_spiR_ptr_;
}

uint32_t *IKESAKeyRequestPacket::getseqPtr()
{
    return keyreq_seq_ptr_;
}

uint16_t *IKESAKeyRequestPacket::getreqlenPtr()
{
    return keyreq_reqlen_ptr_;
}

void IKESAKeyRequestPacket::ConstructIKESAkeyRequestPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::GETKEYIKESA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = IKESAKEYREQUEST_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + length);
    *this->keyreq_spiI_ptr_ = spi_i;
    *this->keyreq_spiR_ptr_ = spi_r;
    *this->keyreq_seq_ptr_ = seq;
    *this->keyreq_reqlen_ptr_ = request_len;
}

void IKESAKeyRequestPacket::ConstructIKESAkeyReturnPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::GETKEYRETURNIKESA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = IKESAKEYREQUEST_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + length);
    *this->keyreq_spiI_ptr_ = spi_i;
    *this->keyreq_spiR_ptr_ = spi_r;
    *this->keyreq_seq_ptr_ = seq;
    *this->keyreq_reqlen_ptr_ = request_len;
    std::memcpy(this->getKeyBufferPtr(), &getkeyvalue[0], getkeyvalue.length());
}
