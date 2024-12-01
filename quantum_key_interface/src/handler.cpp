#include "packet/packets.hpp"
#include "samanagement.hpp"
#include "debuglevel.hpp"
#include "handler.hpp"
#include "server.hpp"

extern SAManager globalSAManager;

// 辅助函数：发送确认消息
void sendConfirmMessage(int fd, ErrorCode errorCode)
{
    ConfirmMessagePacket pktConfirm;
    pktConfirm.constructConfirmMessagePacket(static_cast<uint32_t>(errorCode));
    send(fd, pktConfirm.getBufferPtr(), pktConfirm.getBufferSize(), 0);
}

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
    registeripsecsahdr *hdr = pkt2.getRegisterIPSECSAPacketHeader();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received RegisterIPSECSA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_destination))
                  << " spi: " << std::hex << std::setw(8) << std::setfill('0') << ntohl(hdr->registeripsecsa_spi) << std::dec // 恢复十进制格式
                  << " is_inbound: " << hdr->is_inbound
                  << std::endl;
    }
    // 暂时不作回复
    globalSAManager.registerIPSecSA(ntohl(hdr->registeripsecsa_source), ntohl(hdr->registeripsecsa_destination), hdr->registeripsecsa_spi, hdr->is_inbound);
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
    ipsecsakeyrequesthdr *hdr = pkt2.getKeyRequestHeaderPtr();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received IPSECSAKEYREQUEST packet: "
                  << " spi: " << std::hex << std::setw(8) << std::setfill('0') << ntohl(hdr->keyreq_spi) << std::dec // 恢复十进制格式
                  << " seq: " << hdr->keyreq_seq
                  << " request_len: " << hdr->keyreq_reqlen
                  << std::endl;
    }
    std::string getkeyvalue = globalSAManager.getIPSecKey(hdr->keyreq_spi, hdr->keyreq_seq, hdr->keyreq_reqlen);
    if (getkeyvalue.empty())
    {
        sendConfirmMessage(fd, ErrorCode::GETKEYERROR);
        std::cerr << "Failed to get key!" << std::endl;
        return;
    }
    if (DEBUG_LEVEL == 1)
    {
        // 打印密钥
        for (uint8_t byte : getkeyvalue)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl; // 恢复十进制格式
    }

    // 返回密钥
    IPSECSAKeyRequestPacket pkt3;
    pkt3.ConstructIPSECSAkeyReturnPacket(hdr->keyreq_spi, hdr->keyreq_seq, hdr->keyreq_reqlen, getkeyvalue);
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
    registeripsecsahdr *hdr = pkt2.getRegisterIPSECSAPacketHeader();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received DestoryIPSECSA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_destination))
                  << " spi: " << std::hex << std::setw(8) << std::setfill('0') << ntohl(hdr->registeripsecsa_spi) << std::dec // 恢复十进制格式
                  << " is_inbound: " << hdr->is_inbound
                  << std::endl;
    }
    globalSAManager.destoryIPSecSA(hdr->registeripsecsa_spi);
    close(fd);
}

void handleRegisterIKESAPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // 读取payload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length); // read需要处理，while循环读入
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // 带参构造RegisterIKESAPacket
    RegisterIKESAPacket pkt2(std::move(pkt1));
    registerikesahdr *hdr = pkt2.getRegisterIKESAPacketHeaderPtr();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received RegisterIKESA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_destination))
                  << " spiI: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiI) << std::dec // 恢复十进制格式
                  << " spiR: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiR) << std::dec // 恢复十进制格式
                  << std::endl;
    }
    globalSAManager.registerIKESA(ntohl(hdr->registerikesa_source), ntohl(hdr->registerikesa_destination), hdr->registerikesa_spiI, hdr->registerikesa_spiR);
}

void handleIKESAKeyRequestPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // 读取payload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // 带参构造KeyRequestPacket
    IKESAKeyRequestPacket pkt2(std::move(pkt1));
    ikesakeyrequesthdr *hdr = pkt2.getIKESAKeyRequestHdrPtr();
    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received IKECSAKEYREQUEST packet: "
                  << " spiI: " << std::hex << std::setw(16) << ntohl(hdr->keyreq_spiI) << std::dec // 恢复十进制格式
                  << " spiR: " << std::hex << std::setw(16) << ntohl(hdr->keyreq_spiR) << std::dec // 恢复十进制格式
                  << " seq: " << hdr->keyreq_seq
                  << " request_len: " << hdr->keyreq_reqlen
                  << std::endl;
    }
    std::string getkeyvalue = globalSAManager.getIKESAKey(hdr->keyreq_spiI, hdr->keyreq_spiR, hdr->keyreq_seq, hdr->keyreq_reqlen);
    if (getkeyvalue.empty())
    {
        sendConfirmMessage(fd, ErrorCode::GETKEYERROR);
        std::cerr << "Failed to get key!" << std::endl;
        return;
    }
    if (DEBUG_LEVEL == 1)
    {
        // 打印密钥
        for (uint8_t byte : getkeyvalue)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl; // 恢复十进制格式
    }
    // 返回密钥
    IKESAKeyRequestPacket pkt3;
    pkt3.ConstructIKESAkeyReturnPacket(hdr->keyreq_spiI, hdr->keyreq_spiR, hdr->keyreq_seq, hdr->keyreq_reqlen, getkeyvalue);
    send(fd, pkt3.getBufferPtr(), pkt3.getBufferSize(), 0);
}

void handleDestroyIKESAPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // 读取payload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);
    // 带参构造DestoryPacket
    RegisterIKESAPacket pkt2(std::move(pkt1));
    registerikesahdr *hdr = pkt2.getRegisterIKESAPacketHeaderPtr();
    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received DestoryIKESA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_destination))
                  << " spiI: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiI) << std::dec // 恢复十进制格式
                  << " spiR: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiR) << std::dec // 恢复十进制格式
                  << std::endl;
    }
    globalSAManager.destoryIKESA(hdr->registerikesa_spiI, hdr->registerikesa_spiR);
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
    switch (type)
    {
    case static_cast<uint16_t>(PacketType::REGISTERIKESA):
        return PacketType::REGISTERIKESA;
    case static_cast<uint16_t>(PacketType::GETKEYIKESA):
        return PacketType::GETKEYIKESA;
    case static_cast<uint16_t>(PacketType::DESTORYIKESA):
        return PacketType::DESTORYIKESA;
    case static_cast<uint16_t>(PacketType::REGISTERIPSECSA):
        return PacketType::REGISTERIPSECSA;
    case static_cast<uint16_t>(PacketType::GETKEYIPSECSA):
        return PacketType::GETKEYIPSECSA;
    case static_cast<uint16_t>(PacketType::DESTORYIPSECSA):
        return PacketType::DESTORYIPSECSA;
    default:
        return PacketType::MSG_TYPE_UNKNOWN;
    }
}