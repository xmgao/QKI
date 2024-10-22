#ifndef IPSECSAKEYREQUESTPACKET_HPP
#define IPSECSAKEYREQUESTPACKET_HPP

#include "packetbase.hpp"

#define IPSECSAKEYREQUEST_HEADER_SIZE 10
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
    uint32_t *keyreq_spi_ptr_;
    uint32_t *keyreq_seq_ptr_;
    uint16_t *keyreq_reqlen_ptr_;
    uint8_t *keyreq_payloadptr_;

public:
    IPSECSAKeyRequestPacket();
    explicit IPSECSAKeyRequestPacket(PacketBase &&pkt_base);

    IPSECSAKeyRequestPacket(const IPSECSAKeyRequestPacket &other);
    IPSECSAKeyRequestPacket(IPSECSAKeyRequestPacket &&other) noexcept;

    uint8_t *getKeyBufferPtr();
    uint32_t *getspiPtr();
    uint32_t *getseqPtr();
    uint16_t *getreqlenPtr();

    void ConstructIPSECSAkeyRequestPacket(uint32_t spi, uint32_t seq, uint16_t request_len);

    void ConstructIPSECSAkeyReturnPacket(uint32_t spi, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue);
};

using IPSECSAKeyRequestPacketPtr = std::shared_ptr<IPSECSAKeyRequestPacket>;

#endif