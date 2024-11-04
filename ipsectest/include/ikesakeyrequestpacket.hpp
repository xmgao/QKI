#ifndef IKESAKEYREQUESTPACKET_HPP
#define IKESAKEYREQUESTPACKET_HPP

#include "packetbase.hpp"

#define IKESAKEYREQUEST_HEADER_SIZE 22
/**
 * @brief structure:
 *        |<-4 bytes->|<---8 bytes--->|<---8 bytes--->|<-4 bytes->|<-2 bytes->|<-----------32 bytes---------->|
 *        +-----------+---------------+---------------+-------------------------------------------------------+
 *        | Base hdr  |     spi_I     |     spi_R     |     seq   |  req_len  |           key value           |
 *        +-----------+---------------+---------------+-----------+-----------+-------------------------------+
 *        |<--------------------------------58 bytes max----------------------------------------------------->|
 */

class IKESAKeyRequestPacket : public PacketBase
{
private:
    uint64_t *keyreq_spiI_ptr_;
    uint64_t *keyreq_spiR_ptr_;
    uint32_t *keyreq_seq_ptr_;
    uint16_t *keyreq_reqlen_ptr_;
    uint8_t *keyreq_payloadptr_;

public:
    IKESAKeyRequestPacket();
    explicit IKESAKeyRequestPacket(PacketBase &&pkt_base);

    IKESAKeyRequestPacket(const IKESAKeyRequestPacket &other);
    IKESAKeyRequestPacket(IKESAKeyRequestPacket &&other) noexcept;

    uint8_t *getKeyBufferPtr();
    uint64_t *getspiIPtr();
    uint64_t *getspiRPtr();
    uint32_t *getseqPtr();
    uint16_t *getreqlenPtr();

    void ConstructIKESAkeyRequestPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len);
    void ConstructIKESAkeyReturnPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue);
};

using IKESAKeyRequestPacketPtr = std::shared_ptr<IKESAKeyRequestPacket>;

#endif