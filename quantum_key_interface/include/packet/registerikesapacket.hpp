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

struct __attribute__((packed)) registerikesahdr_struct
{
    uint32_t registerikesa_source;
    uint32_t registerikesa_destination;
    uint64_t registerikesa_spiI;
    uint64_t registerikesa_spiR;
};

using registerikesahdr = struct registerikesahdr_struct;

constexpr size_t REGISTERIKESA_HEADER_SIZE = sizeof(registerikesahdr);

class RegisterIKESAPacket : public PacketBase
{
private:
    registerikesahdr *registerikesahdr_ptr;

public:
    RegisterIKESAPacket();
    explicit RegisterIKESAPacket(PacketBase &&pkt_base);

    RegisterIKESAPacket(const RegisterIKESAPacket &other);
    RegisterIKESAPacket(RegisterIKESAPacket &&other) noexcept;

    registerikesahdr *getRegisterIKESAPacketHeaderPtr();

    void ConstructRegisterIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r);

    void ConstructDestoryIKESAPacket(uint32_t sourceip_, uint32_t desip_, uint64_t spi_i, uint64_t spi_r);
};

using RegisterIKESAPacketPtr = std::shared_ptr<RegisterIKESAPacket>;

#endif