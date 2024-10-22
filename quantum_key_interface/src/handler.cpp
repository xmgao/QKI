#include "packet/packets.hpp"
#include "samanagement.hpp"
#include "debuglevel.hpp"
#include "handler.hpp"
#include "server.hpp"

extern SAManager globalSAManager;

// ����IPSECSAע������
void handleRegisterIPSECSAPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // ��ȡpayload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length); // read��Ҫ����whileѭ������
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // ���ι���RegisterIPSECSAPacket
    RegisterIPSECSAPacket pkt2(std::move(pkt1));
    uint32_t sourceip = *pkt2.getsourcePtr();
    uint32_t desip = *pkt2.getdesPtr();
    uint32_t spi = *pkt2.getspiPtr();
    bool is_inbound = *pkt2.getinboundPtr();
    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received RegisterIPSECSA packet: "
                  << " source_ip: " << uint32ToIpString(sourceip)
                  << " dest_ip: " << uint32ToIpString(desip)
                  << " spi: " << spi
                  << " is_inbound: " << is_inbound
                  << std::endl;
    }
    globalSAManager.registerSA(sourceip, desip, spi, is_inbound);

}

// ����IPSECSA��ȡ��Կ
void handleIPSECSAKeyRequestPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // ��ȡpayload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // ���ι���KeyRequestPacket
    IPSECSAKeyRequestPacket pkt2(std::move(pkt1));
    uint32_t spi = *pkt2.getspiPtr();
    uint32_t seq = *pkt2.getseqPtr();
    uint16_t request_len = *pkt2.getreqlenPtr();
    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received IPSECSAKEYREQUEST packet: "
                  << " spi: " << spi
                  << " seq: " << seq
                  << " request_len: " << request_len
                  << std::endl;
    }
    std::string getkeyvalue = globalSAManager.getKey(spi, seq, request_len);
    // ������Կ
    IPSECSAKeyRequestPacket pkt3;
    pkt3.ConstructIPSECSAkeyReturnPacket(spi, seq, request_len, getkeyvalue);
    send(fd, pkt3.getBufferPtr(), pkt3.getBufferSize(), 0);
}

// ����IPSECSA
void handleDestroyIPSECSAPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // ��ȡpayload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);
    // ���ι���CloseSessionPacket
    RegisterIPSECSAPacket pkt2(std::move(pkt1));
    uint32_t sourceip = *pkt2.getsourcePtr();
    uint32_t desip = *pkt2.getdesPtr();
    uint32_t spi = *pkt2.getspiPtr();
    bool is_inbound = *pkt2.getinboundPtr();
    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received CLOSESESSION packet: "
                  << " source_ip: " << uint32ToIpString(sourceip)
                  << " dest_ip: " << uint32ToIpString(desip)
                  << " spi: " << spi
                  << " is_inbound: " << is_inbound
                  << std::endl;
    }
    globalSAManager.destorySA(spi);
    close(fd);
}

// ����UNKOWN_TYPE������Type����Length��ȷ
void handleUnknownPacket(int fd, PacketBase &pkt)
{
    std::cout << "Received UNKOWN_TYPE!" << std::endl;
    // ��ȡ������δ֪��Ϣ
    char buffer[MAX_BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0)
    {
        // ������ȡ��ֱ��������Ϊ��
    }
    // �򵥻ظ�
    ConfirmMessagePacket pkt3;
    pkt3.constructConfirmMessagePacket(static_cast<uint32_t>(ErrorCode::UNKONWNMESSAGE));
    send(fd, pkt3.getBufferPtr(), pkt3.getBufferSize(), 0);
    close(fd);
}

// ģ�����Ϣ�н���������
PacketType parsePacketType(uint16_t type)
{
    if (type == static_cast<uint16_t>(PacketType::REGISTERIKESA))
        return PacketType::REGISTERIKESA;
    if (type == static_cast<uint16_t>(PacketType::GETKEYIKESA))
        return PacketType::GETKEYIKESA;
    if (type == static_cast<uint16_t>(PacketType::DESTORYIKESA))
        return PacketType::DESTORYIKESA;
    if (type == static_cast<uint16_t>(PacketType::REGISTERIPSECSA))
        return PacketType::REGISTERIPSECSA;
    if (type == static_cast<uint16_t>(PacketType::GETKEYIPSECSA))
        return PacketType::GETKEYIPSECSA;
    if (type == static_cast<uint16_t>(PacketType::DESTORYIPSECSA))
        return PacketType::DESTORYIPSECSA;
    return PacketType::MSG_TYPE_UNKNOWN;
}
