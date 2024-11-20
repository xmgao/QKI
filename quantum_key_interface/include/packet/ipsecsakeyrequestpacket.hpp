#ifndef IPSECSAKEYREQUESTPACKET_HPP
#define IPSECSAKEYREQUESTPACKET_HPP

#include "packetbase.hpp"

struct __attribute__((packed)) ipsecsakeyrequesthdr_struct
{
    uint32_t keyreq_spi;
    uint32_t keyreq_seq;
    uint16_t keyreq_reqlen;
};

using ipsecsakeyrequesthdr = struct ipsecsakeyrequesthdr_struct;

constexpr size_t IPSECSAKEYREQUEST_HEADER_SIZE = sizeof(ipsecsakeyrequesthdr);

/**
 * @brief structure:
 *        |<-4 bytes->|<-4 bytes->|<-4 bytes->|<-2 bytes->|<----------512 bytes---------->|
 *        +-----------+-----------+-------------------------------------------------------+
 *        | Base hdr  |   SPI     |     seq   |  req_len  |           key value           |
 *        +-----------+-----------+-------------------------------------------------------+
 *        |<------------------------------526 bytes max---------------------------------->|
 */

class IPSECSAKeyRequestPacket : public PacketBase
{
private:
    ipsecsakeyrequesthdr *keyreq_hdrptr_;
    uint8_t *keyreq_payloadptr_;

public:
    IPSECSAKeyRequestPacket();
    explicit IPSECSAKeyRequestPacket(PacketBase &&pkt_base);

    IPSECSAKeyRequestPacket(const IPSECSAKeyRequestPacket &other);
    IPSECSAKeyRequestPacket(IPSECSAKeyRequestPacket &&other) noexcept;

    uint8_t *getKeyBufferPtr();
    ipsecsakeyrequesthdr * getKeyRequestHeaderPtr();

    void ConstructIPSECSAkeyRequestPacket(uint32_t spi, uint32_t seq, uint16_t request_len);

    void ConstructIPSECSAkeyReturnPacket(uint32_t spi, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue);
};

using IPSECSAKeyRequestPacketPtr = std::shared_ptr<IPSECSAKeyRequestPacket>;

#endif