#include "packet/ikesakeyrequestpacket.hpp"

IKESAKeyRequestPacket::IKESAKeyRequestPacket()
    : keyreq_hdrptr_(reinterpret_cast<ikesakeyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IKESAKEYREQUESTHDR_SIZE) {}

IKESAKeyRequestPacket::IKESAKeyRequestPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      keyreq_hdrptr_(reinterpret_cast<ikesakeyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IKESAKEYREQUESTHDR_SIZE) {}

IKESAKeyRequestPacket::IKESAKeyRequestPacket(const IKESAKeyRequestPacket &other)
    : PacketBase(other),
      keyreq_hdrptr_(reinterpret_cast<ikesakeyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + IKESAKEYREQUESTHDR_SIZE) {}

IKESAKeyRequestPacket::IKESAKeyRequestPacket(IKESAKeyRequestPacket &&other) noexcept = default;

uint8_t *IKESAKeyRequestPacket::getKeyBufferPtr()
{
    return keyreq_payloadptr_;
}

ikesakeyrequesthdr *IKESAKeyRequestPacket::getIKESAKeyRequestHdrPtr()
{
    return keyreq_hdrptr_;
}

void IKESAKeyRequestPacket::ConstructIKESAkeyRequestPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::GETKEYIKESA);
    header_->packet_length = IKESAKEYREQUESTHDR_SIZE;
    keyreq_hdrptr_->keyreq_spiI = spi_i;
    keyreq_hdrptr_->keyreq_spiR = spi_r;
    keyreq_hdrptr_->keyreq_seq = seq;
    keyreq_hdrptr_->keyreq_reqlen = request_len;
    this->setBufferSize(BASE_HEADER_SIZE + IKESAKEYREQUESTHDR_SIZE);
}

void IKESAKeyRequestPacket::ConstructIKESAkeyReturnPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::GETKEYRETURNIKESA);
    header_->packet_length = IKESAKEYREQUESTHDR_SIZE + getkeyvalue.length();
    keyreq_hdrptr_->keyreq_spiI = spi_i;
    keyreq_hdrptr_->keyreq_spiR = spi_r;
    keyreq_hdrptr_->keyreq_seq = seq;
    keyreq_hdrptr_->keyreq_reqlen = request_len;
    this->setBufferSize(BASE_HEADER_SIZE + IKESAKEYREQUESTHDR_SIZE + getkeyvalue.length());
    std::memcpy(this->getKeyBufferPtr(), &getkeyvalue[0], getkeyvalue.length());
}
