#ifndef IKESAKEYREQUESTPACKET_HPP
#define IKESAKEYREQUESTPACKET_HPP

#include "packetbase.hpp"


struct __attribute__((packed)) ikesakeyrequesthdr_struct
{
    uint64_t keyreq_spiI;
    uint64_t keyreq_spiR;
    uint32_t keyreq_seq; // sequence number
    uint16_t keyreq_reqlen;
};

using ikesakeyrequesthdr = struct ikesakeyrequesthdr_struct;

constexpr size_t IKESAKEYREQUESTHDR_SIZE = sizeof(ikesakeyrequesthdr);

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
    ikesakeyrequesthdr *keyreq_hdrptr_;
    uint8_t *keyreq_payloadptr_;

public:
    IKESAKeyRequestPacket();
    explicit IKESAKeyRequestPacket(PacketBase &&pkt_base);

    IKESAKeyRequestPacket(const IKESAKeyRequestPacket &other);
    IKESAKeyRequestPacket(IKESAKeyRequestPacket &&other) noexcept;

    ikesakeyrequesthdr *getIKESAKeyRequestHdrPtr();
    uint8_t *getKeyBufferPtr();

    void ConstructIKESAkeyRequestPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len);
    void ConstructIKESAkeyReturnPacket(uint64_t spi_i, uint64_t spi_r, uint32_t seq, uint16_t request_len, const std::string &getkeyvalue);
};

using IKESAKeyRequestPacketPtr = std::shared_ptr<IKESAKeyRequestPacket>;

#endif