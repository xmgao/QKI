#include "packet/packets.hpp"
#include "samanagement.hpp"
#include "debuglevel.hpp"
#include "handler.hpp"
#include "server.hpp"

extern SAManager globalSAManager;

// 处理IPSECSA注册请求
void handleRegisterIPSECSAPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // 读取payload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length); // read需要处理，while循环读入
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // 带参构造RegisterIPSECSAPacket
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

// 处理IPSECSA获取密钥
void handleIPSECSAKeyRequestPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // 读取payload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // 带参构造KeyRequestPacket
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
    // 返回密钥
    IPSECSAKeyRequestPacket pkt3;
    pkt3.ConstructIPSECSAkeyReturnPacket(spi, seq, request_len, getkeyvalue);
    send(fd, pkt3.getBufferPtr(), pkt3.getBufferSize(), 0);
}

// 销毁IPSECSA
void handleDestroyIPSECSAPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // 读取payload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);
    // 带参构造CloseSessionPacket
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

// 处理UNKOWN_TYPE，假设Type错误，Length正确
void handleUnknownPacket(int fd, PacketBase &pkt)
{
    std::cout << "Received UNKOWN_TYPE!" << std::endl;
    // 读取并丢弃未知消息
    char buffer[MAX_BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0)
    {
        // 继续读取，直到缓冲区为空
    }
    // 简单回复
    ConfirmMessagePacket pkt3;
    pkt3.constructConfirmMessagePacket(static_cast<uint32_t>(ErrorCode::UNKONWNMESSAGE));
    send(fd, pkt3.getBufferPtr(), pkt3.getBufferSize(), 0);
    close(fd);
}

// 模拟从消息中解析出类型
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
