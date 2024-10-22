#include "packet/ipsecsakeyrequestpacket.hpp"

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket()
    : keyreq_spi_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_seq_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE) {}

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      keyreq_spi_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_seq_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE) {}

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket(const IPSECSAKeyRequestPacket &other)
    : PacketBase(other),
      keyreq_spi_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_seq_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE) {}

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket(IPSECSAKeyRequestPacket &&other) noexcept = default;

uint8_t *IPSECSAKeyRequestPacket::getKeyBufferPtr()
{
    return keyreq_payloadptr_;
}

uint32_t *IPSECSAKeyRequestPacket::getspiPtr()
{
    return keyreq_spi_ptr_;
}

uint32_t *IPSECSAKeyRequestPacket::getseqPtr()
{
    return keyreq_seq_ptr_;
}

uint16_t *IPSECSAKeyRequestPacket::getreqlenPtr()
{
    return keyreq_reqlen_ptr_;
}

void IPSECSAKeyRequestPacket::ConstructIPSECSAkeyRequestPacket(uint32_t spi, uint32_t seq, uint16_t request_len)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::GETKEYIPSECSA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = IPSECSAKEYREQUEST_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + length);
    *this->keyreq_spi_ptr_ = spi;
    *this->keyreq_seq_ptr_ = seq;
    *this->keyreq_reqlen_ptr_ = request_len;
}

void IPSECSAKeyRequestPacket::ConstructIPSECSAkeyReturnPacket(uint32_t spi, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue)
{

    uint16_t intvalue = static_cast<uint16_t>(PacketType::GETKEYRETURNIPSECSA);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = IPSECSAKEYREQUEST_HEADER_SIZE + getkeyvalue.length();
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + length);
    *this->keyreq_spi_ptr_ = spi;
    *this->keyreq_seq_ptr_ = seq;
    *this->keyreq_reqlen_ptr_ = request_len;
    std::memcpy(this->getKeyBufferPtr(), &getkeyvalue[0], getkeyvalue.length());
}
