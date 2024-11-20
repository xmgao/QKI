#ifndef KEYREQUESTPACKET_HPP
#define KEYREQUESTPACKET_HPP

#include "packetbase.hpp"

struct __attribute__((packed)) keyrequesthdr_struct
{
    uint32_t keyreq_sessid;
    uint32_t keyreq_reqid;
    uint16_t keyreq_reqlen;
};

using keyrequesthdr = struct keyrequesthdr_struct;

constexpr size_t KEYREQUEST_HEADER_SIZE = sizeof(keyrequesthdr);

/**
 * @brief structure:
 *        |<-4 bytes->|<-4 bytes->|<-4 bytes->|<-2 bytes->|<----------512 bytes---------->|
 *        +-----------+-----------+-------------------------------------------------------+
 *        | Base hdr  |  sess_id  |   req_id  |  req_len  |           key value           |
 *        +-----------+-----------+-------------------------------------------------------+
 *        |<------------------------------526 bytes max---------------------------------->|
 */

class KeyRequestPacket : public PacketBase
{
private:
    keyrequesthdr *keyreq_hdrptr_;
    uint8_t *keyreq_payloadptr_;

public:
    KeyRequestPacket();
    explicit KeyRequestPacket(PacketBase &&pkt_base);

    KeyRequestPacket(const KeyRequestPacket &other);
    KeyRequestPacket(KeyRequestPacket &&other) noexcept;

    uint8_t *getKeyBufferPtr();
    keyrequesthdr *getKeyRequestHeaderPtr();

    void constructkeyrequestpacket(uint32_t session_id, uint32_t request_id, uint16_t request_len);

    void constructkeyreturnpacket(uint32_t session_id, uint32_t request_id, uint16_t request_len, const std::string &getkeyvalue);
};

using KeyRequestPacketPtr = std::shared_ptr<KeyRequestPacket>;

#endif