#ifndef REGISTERIPSECSAPACKET_HPP
#define REGISTERIPSECSAPACKET_HPP

#include "packetbase.hpp"

/**
 * @brief structure:
 *        |<-4 bytes->|<-4 bytes->|<-4 bytes->|<-4 bytes->|<-1 bytes->|
 *        +-----------+-----------+-----------------------------------+
 *        | Base hdr  |sourece_ip | dest_ip   |   spi     | is_inbound|
 *        +-----------+-----------+-----------------------------------+
 *        |<---------------------17 bytes max------------------------>|
 */

#define REGISTERIPSECSA_HEADER_SIZE 13

class RegisterIPSECSAPacket : public PacketBase
{
private:
    uint32_t *registeripsecsa_source_ptr_;
    uint32_t *registeripsecsa_destination_ptr_;
    uint32_t *registeripsecsa_spi_ptr_;
    bool *is_inbound_ptr_;

public:
    RegisterIPSECSAPacket();
    explicit RegisterIPSECSAPacket(PacketBase &&pkt_base);

    RegisterIPSECSAPacket(const RegisterIPSECSAPacket &other);
    RegisterIPSECSAPacket(RegisterIPSECSAPacket &&other) noexcept;

    uint32_t *getsourcePtr();
    uint32_t *getdesPtr();
    uint32_t *getspiPtr();
    bool *getinboundPtr();

    void ConstructRegisterIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi, bool is_inbound);

    void ConstructDestoryIPSECSAPacket(uint32_t sourceip_, uint32_t desip_, uint32_t spi, bool is_inbound);
};

using RegisterIPSECSAPacketPtr = std::shared_ptr<RegisterIPSECSAPacket>;

#endif