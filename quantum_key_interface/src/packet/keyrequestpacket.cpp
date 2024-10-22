#include "packet/keyrequestpacket.hpp"


KeyRequestPacket::KeyRequestPacket()
    : keyreq_sessid_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_reqid_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE) {}

KeyRequestPacket::KeyRequestPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      keyreq_sessid_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_reqid_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE) {}

KeyRequestPacket::KeyRequestPacket(const KeyRequestPacket &other)
    : PacketBase(other),
      keyreq_sessid_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE)),
      keyreq_reqid_ptr_(reinterpret_cast<uint32_t *>(buffer_ + BASE_HEADER_SIZE + sizeof(uint32_t))),
      keyreq_reqlen_ptr_(reinterpret_cast<uint16_t *>(buffer_ + BASE_HEADER_SIZE + 2 * sizeof(uint32_t))),
      keyreq_payloadptr_(buffer_ + BASE_HEADER_SIZE + KEYREQUEST_HEADER_SIZE) {}

KeyRequestPacket::KeyRequestPacket(KeyRequestPacket &&other) noexcept = default;

uint8_t *KeyRequestPacket::getKeyBufferPtr()
{
    return keyreq_payloadptr_;
}

uint32_t *KeyRequestPacket::getsessidPtr()
{
    return keyreq_sessid_ptr_;
}

uint32_t *KeyRequestPacket::getreqidPtr()
{
    return keyreq_reqid_ptr_;
}

uint16_t *KeyRequestPacket::getreqlenPtr()
{
    return keyreq_reqlen_ptr_;
}

void KeyRequestPacket::constructkeyrequestpacket(uint32_t session_id, uint32_t request_id, uint16_t request_len)
{
    uint16_t intvalue = static_cast<uint16_t>(PacketType::KEYREQUEST);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = KEYREQUEST_HEADER_SIZE;
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + length);
    *this->keyreq_sessid_ptr_ = session_id;
    *this->keyreq_reqid_ptr_ = request_id;
    *this->keyreq_reqlen_ptr_ = request_len;
}

void KeyRequestPacket::constructkeyreturnpacket(uint32_t session_id, uint32_t request_id, uint16_t request_len, const std::string &getkeyvalue)
{

    uint16_t intvalue = static_cast<uint16_t>(PacketType::KEYRETURN);
    std::memcpy(this->getBufferPtr(), &intvalue, sizeof(uint16_t));
    uint16_t length = KEYREQUEST_HEADER_SIZE + getkeyvalue.length();
    std::memcpy(this->getBufferPtr() + sizeof(uint16_t), &length, sizeof(uint16_t));
    this->setBufferSize(BASE_HEADER_SIZE + length);
    *this->keyreq_sessid_ptr_ = session_id;
    *this->keyreq_reqid_ptr_ = request_id;
    *this->keyreq_reqlen_ptr_ = request_len;

    std::memcpy(this->getKeyBufferPtr(), &getkeyvalue[0], getkeyvalue.length());
}
