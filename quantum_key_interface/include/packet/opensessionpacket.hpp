#ifndef OPENSESSIONPACKET_HPP
#define OPENSESSIONPACKET_HPP

#include "packetbase.hpp"

/**
 * @brief structure:
 *        |<-4 bytes->|<-4 bytes->|<-4 bytes->|<-4 bytes->|<-1 bytes->|
 *        +-----------+-----------+-----------------------------------+
 *        | Base hdr  |  sourece  | destinaton|   sess_id |is_inbound |
 *        +-----------+-----------+-----------------------------------+
 *        |<---------------------17 bytes max------------------------>|
 */

struct __attribute__((packed)) opensessionhdr_struct
{
    uint32_t opensession_source;
    uint32_t opensession_destination;
    uint32_t opensession_session;
    bool is_inbound;
};

using opensessionhdr = struct opensessionhdr_struct;

constexpr size_t OPENSESSION_HEADER_SIZE = sizeof(opensessionhdr);

class OpenSessionPacket : public PacketBase
{
private:
    opensessionhdr *opensession_header_ptr;

public:
    OpenSessionPacket();
    explicit OpenSessionPacket(PacketBase &&pkt_base);

    OpenSessionPacket(const OpenSessionPacket &other);
    OpenSessionPacket(OpenSessionPacket &&other) noexcept;

    opensessionhdr *get_opensession_header_ptr();

    void constructopensessionpacket(uint32_t sourceip_, uint32_t desip_, uint32_t session_id, bool is_inbound);

    void constructclosesessionpacket(uint32_t sourceip_, uint32_t desip_, uint32_t session_id, bool is_inbound);
};

using OpenSessionPacketPtr = std::shared_ptr<OpenSessionPacket>;

#endif