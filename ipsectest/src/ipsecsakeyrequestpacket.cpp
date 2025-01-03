#include "ipsecsakeyrequestpacket.hpp"

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket()
    : keyreq_hdrptr_(reinterpret_cast<ipsecsakeyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE) {}

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      keyreq_hdrptr_(reinterpret_cast<ipsecsakeyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE) {}

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket(const IPSECSAKeyRequestPacket &other)
    : PacketBase(other),
      keyreq_hdrptr_(reinterpret_cast<ipsecsakeyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE) {}

IPSECSAKeyRequestPacket::IPSECSAKeyRequestPacket(IPSECSAKeyRequestPacket &&other) noexcept = default;

uint8_t *IPSECSAKeyRequestPacket::getKeyBufferPtr()
{
    return keyreq_payloadptr_;
}

ipsecsakeyrequesthdr *IPSECSAKeyRequestPacket::getKeyRequestHeaderPtr()
{
    return keyreq_hdrptr_;
}

void IPSECSAKeyRequestPacket::ConstructIPSECSAkeyRequestPacket(uint32_t spi, uint32_t seq, uint16_t request_len)
{

    header_->packet_type = static_cast<uint16_t>(PacketType::GETKEYIPSECSA);
    header_->packet_length = IPSECSAKEYREQUEST_HEADER_SIZE;
    keyreq_hdrptr_->keyreq_spi = spi;
    keyreq_hdrptr_->keyreq_seq = seq;
    keyreq_hdrptr_->keyreq_reqlen = request_len;
    this->setBufferSize(BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE);
}

void IPSECSAKeyRequestPacket::ConstructIPSECSAkeyReturnPacket(uint32_t spi, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue)
{

    header_->packet_type = static_cast<uint16_t>(PacketType::GETKEYRETURNIPSECSA);
    header_->packet_length = IPSECSAKEYREQUEST_HEADER_SIZE + getkeyvalue.length();
    keyreq_hdrptr_->keyreq_spi = spi;
    keyreq_hdrptr_->keyreq_seq = seq;
    keyreq_hdrptr_->keyreq_reqlen = request_len;
    this->setBufferSize(BASE_HEADER_SIZE + IPSECSAKEYREQUEST_HEADER_SIZE + getkeyvalue.length());
    std::memcpy(this->getKeyBufferPtr(), &getkeyvalue[0], getkeyvalue.length());
}
