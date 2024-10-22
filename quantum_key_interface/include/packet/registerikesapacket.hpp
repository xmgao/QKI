#ifndef REGISTERIKESAPACKET_HPP
#define REGISTERIKESAPACKET_HPP

#include "packetbase.hpp"

/**
 * @brief structure:
 *        |<-4 bytes->|<-4 bytes->|<-4 bytes->|<---8 bytes--->|<---8 bytes--->|
 *        +-----------+-----------+-------------------------------------------+
 *        | Base hdr  |sourece_ip | dest_ip   |     spi_I     |     spi_R     |
 *        +-----------+-----------+-------------------------------------------+
 *        |<---------------------28 bytes max-------------------------------->|
 */

#define REGISTERIKESA_HEADER_SIZE 24

class RegisterIKESAPacket : public PacketBase
{
private:
    uint32_t *registerikesa_source_ptr_;
    uint32_t *registerikesa_destination_ptr_;
    uint64_t *registerikesa_spiI_ptr_;
    uint64_t *registerikesa_spiR_ptr_;

public:
    RegisterIKESAPacket();
    explicit RegisterIKESAPacket(PacketBase &&pkt_base);

    RegisterIKESAPacket(const RegisterIKESAPacket &other);
    RegisterIKESAPacket(RegisterIKESAPacket &&other) noexcept;

    uint32_t *getsourcePtr();
    uint32_t *getdesPtr();
    uint64_t *getspiIPtr();
    uint64_t *getspiRPtr();

    void ConstructRegisterIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r);

    void ConstructDestoryIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r);
};

using RegisterIKESAPacketPtr = std::shared_ptr<RegisterIKESAPacket>;

#endif