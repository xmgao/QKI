#ifndef REGISTERIPSECSAPACKET_HPP
#define REGISTERIPSECSAPACKET_HPP

#include "packetbase.hpp"

/**
 * @brief structure:
 *        |<-4 bytes->|<-4 bytes->|<-4 bytes->|<-4 bytes->|<-1 bytes->|<-1 bytes->|
 *        +-----------+-----------+-----------------------------------------------+
 *        | Base hdr  |sourece_ip | dest_ip   |   spi     | is_inbound| is_otpalg |
 *        +-----------+-----------+-----------------------------------------------+
 *        |<---------------------18 bytes max------------------------------------>|
 */

struct __attribute__((packed)) registeripsecsahdr_struct
{
    uint32_t registeripsecsa_source;
    uint32_t registeripsecsa_destination;
    uint32_t registeripsecsa_spi;
    uint8_t is_inbound;
    uint8_t is_otpalg;
};

using registeripsecsahdr = struct registeripsecsahdr_struct;

constexpr size_t REGISTERIPSECSA_HEADER_SIZE = sizeof(registeripsecsahdr);

class RegisterIPSECSAPacket : public PacketBase
{
private:
    registeripsecsahdr *registeripsecsa_header_ptr;

public:
    RegisterIPSECSAPacket();
    explicit RegisterIPSECSAPacket(PacketBase &&pkt_base);

    RegisterIPSECSAPacket(const RegisterIPSECSAPacket &other);
    RegisterIPSECSAPacket(RegisterIPSECSAPacket &&other) noexcept;

    registeripsecsahdr *getRegisterIPSECSAPacketHeader();

    void ConstructRegisterIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi, bool is_inbound, bool is_otpalg);

    void ConstructDestoryIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi, bool is_inbound, bool is_otpalg);
};

using RegisterIPSECSAPacketPtr = std::shared_ptr<RegisterIPSECSAPacket>;

#endif