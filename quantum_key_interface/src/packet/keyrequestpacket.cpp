#include "packet/keyrequestpacket.hpp"

KeyRequestPacket::KeyRequestPacket()
    : keyreq_hdrptr_(reinterpret_cast<keyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE) {}

KeyRequestPacket::KeyRequestPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      keyreq_hdrptr_(reinterpret_cast<keyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE) {}

KeyRequestPacket::KeyRequestPacket(const KeyRequestPacket &other)
    : PacketBase(other),
      keyreq_hdrptr_(reinterpret_cast<keyrequesthdr *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE) {}

KeyRequestPacket::KeyRequestPacket(KeyRequestPacket &&other) noexcept = default;

uint8_t *KeyRequestPacket::getKeyBufferPtr()
{
    return keyreq_payloadptr_;
}

keyrequesthdr *KeyRequestPacket::getKeyRequestHeaderPtr()
{
    return keyreq_hdrptr_;
}

void KeyRequestPacket::constructkeyrequestpacket(uint32_t session_id, uint32_t request_id, uint16_t request_len)
{

    header_->packet_type = static_cast<uint16_t>(PacketType::KEYREQUEST);
    header_->packet_length = KEYREQUEST_HEADER_SIZE;
    keyreq_hdrptr_->keyreq_sessid = session_id;
    keyreq_hdrptr_->keyreq_reqid = request_id;
    keyreq_hdrptr_->keyreq_reqlen = request_len;
    this->setBufferSize(BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE);
}

void KeyRequestPacket::constructkeyreturnpacket(uint32_t session_id, uint32_t request_id, uint16_t request_len, const std::string &getkeyvalue)
{

    header_->packet_type = static_cast<uint16_t>(PacketType::KEYRETURN);
    header_->packet_length = KEYREQUEST_HEADER_SIZE + getkeyvalue.length();
    keyreq_hdrptr_->keyreq_sessid = session_id;
    keyreq_hdrptr_->keyreq_reqid = request_id;
    keyreq_hdrptr_->keyreq_reqlen = request_len;
    this->setBufferSize(BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE + getkeyvalue.length());
    std::memcpy(this->getKeyBufferPtr(), &getkeyvalue[0], getkeyvalue.length());
}
