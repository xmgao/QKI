#ifndef ConfirmMessagePacket_HPP
#define ConfirmMessagePacket_HPP

#include "packetbase.hpp"

/**
 * @brief structure:
 *        |<-4 bytes->|<-4 bytes->|
 *        +-----------+-----------+
 *        | Base hdr  | Error Type|
 *        +-----------+-----------+
 *        |<-------8 bytes max--->|
 */

#define CONFIRMMESSAGE_HEADER_SIZE 4

enum class ErrorCode : uint32_t
{
    SUCCESS = 0,
    OPENSESSIONERROR,
    GETKEYERROR,
    UNKONWNMESSAGE,
    RIGISTERIKESAERROR,
    REGISETRIPSECSAERROR
};

class ConfirmMessagePacket : public PacketBase
{
private:
    uint32_t *error_type_ptr_;

public:
    ConfirmMessagePacket();
    explicit ConfirmMessagePacket(PacketBase &&pkt_base);

    ConfirmMessagePacket(const ConfirmMessagePacket &other);
    ConfirmMessagePacket(ConfirmMessagePacket &&other) noexcept;

    uint32_t *geterrortypePtr();

    void constructConfirmMessagePacket(uint32_t errortype);
};

using ConfirmMessagePacketPtr = std::shared_ptr<ConfirmMessagePacket>;

#endif
