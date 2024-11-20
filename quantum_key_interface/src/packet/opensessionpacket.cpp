#include "packet/opensessionpacket.hpp"

OpenSessionPacket::OpenSessionPacket()
    : opensession_header_ptr(reinterpret_cast<opensessionhdr *>(buffer_ + BASE_HEADER_SIZE)) {}

OpenSessionPacket::OpenSessionPacket(PacketBase &&pkt_base)
    : PacketBase(std::move(pkt_base)),
      opensession_header_ptr(reinterpret_cast<opensessionhdr *>(buffer_ + BASE_HEADER_SIZE)) {}

OpenSessionPacket::OpenSessionPacket(const OpenSessionPacket &other)
    : PacketBase(other),
      opensession_header_ptr(reinterpret_cast<opensessionhdr *>(buffer_ + BASE_HEADER_SIZE)) {}

OpenSessionPacket::OpenSessionPacket(OpenSessionPacket &&other) noexcept = default;

opensessionhdr *OpenSessionPacket::get_opensession_header_ptr()
{
    return opensession_header_ptr;
}

void OpenSessionPacket::constructopensessionpacket(uint32_t sourceip_, uint32_t desip_, uint32_t session_id, bool is_inbound)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::OPENSESSION);
    header_->packet_length = OPENSESSION_HEADER_SIZE;
    opensession_header_ptr->opensession_source = sourceip_;
    opensession_header_ptr->opensession_destination = desip_;
    opensession_header_ptr->opensession_session = session_id;
    opensession_header_ptr->is_inbound = is_inbound; // 0 for outbound, 1 for inbound
    this->setBufferSize(BASE_HEADER_SIZE + OPENSESSION_HEADER_SIZE);
}

void OpenSessionPacket::constructclosesessionpacket(uint32_t sourceip_, uint32_t desip_, uint32_t session_id, bool is_inbound)
{
    header_->packet_type = static_cast<uint16_t>(PacketType::CLOSESESSION);
    header_->packet_length = OPENSESSION_HEADER_SIZE;
    opensession_header_ptr->opensession_source = sourceip_;
    opensession_header_ptr->opensession_destination = desip_;
    opensession_header_ptr->opensession_session = session_id;
    opensession_header_ptr->is_inbound = is_inbound; // 0 for outbound, 1 for inbound
    this->setBufferSize(BASE_HEADER_SIZE + OPENSESSION_HEADER_SIZE);
}
