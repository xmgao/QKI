#include "packet/packets.hpp"
#include "samanagement.hpp"
#include "debuglevel.hpp"
#include "handler.hpp"
#include "server.hpp"

extern SAManager globalSAManager;

// ��������������ȷ����Ϣ
void sendConfirmMessage(int fd, ErrorCode errorCode)
{
    ConfirmMessagePacket pktConfirm;
    pktConfirm.constructConfirmMessagePacket(static_cast<uint32_t>(errorCode));
    send(fd, pktConfirm.getBufferPtr(), pktConfirm.getBufferSize(), 0);
}

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
    registeripsecsahdr *hdr = pkt2.getRegisterIPSECSAPacketHeader();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received RegisterIPSECSA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_destination))
                  << " spi: " << std::hex << std::setw(8) << std::setfill('0') << ntohl(hdr->registeripsecsa_spi) << std::dec // �ָ�ʮ���Ƹ�ʽ
                  << " is_inbound: " << hdr->is_inbound
                  << std::endl;
    }
    // ��ʱ�����ظ�
    globalSAManager.registerIPSecSA(ntohl(hdr->registeripsecsa_source), ntohl(hdr->registeripsecsa_destination), hdr->registeripsecsa_spi, hdr->is_inbound);
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
    ipsecsakeyrequesthdr *hdr = pkt2.getKeyRequestHeaderPtr();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received IPSECSAKEYREQUEST packet: "
                  << " spi: " << std::hex << std::setw(8) << std::setfill('0') << ntohl(hdr->keyreq_spi) << std::dec // �ָ�ʮ���Ƹ�ʽ
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
        // ��ӡ��Կ
        for (uint8_t byte : getkeyvalue)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl; // �ָ�ʮ���Ƹ�ʽ
    }

    // ������Կ
    IPSECSAKeyRequestPacket pkt3;
    pkt3.ConstructIPSECSAkeyReturnPacket(hdr->keyreq_spi, hdr->keyreq_seq, hdr->keyreq_reqlen, getkeyvalue);
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
    registeripsecsahdr *hdr = pkt2.getRegisterIPSECSAPacketHeader();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received DestoryIPSECSA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registeripsecsa_destination))
                  << " spi: " << std::hex << std::setw(8) << std::setfill('0') << ntohl(hdr->registeripsecsa_spi) << std::dec // �ָ�ʮ���Ƹ�ʽ
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
    // ��ȡpayload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length); // read��Ҫ����whileѭ������
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // ���ι���RegisterIKESAPacket
    RegisterIKESAPacket pkt2(std::move(pkt1));
    registerikesahdr *hdr = pkt2.getRegisterIKESAPacketHeaderPtr();

    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received RegisterIKESA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_destination))
                  << " spiI: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiI) << std::dec // �ָ�ʮ���Ƹ�ʽ
                  << " spiR: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiR) << std::dec // �ָ�ʮ���Ƹ�ʽ
                  << std::endl;
    }
    globalSAManager.registerIKESA(ntohl(hdr->registerikesa_source), ntohl(hdr->registerikesa_destination), hdr->registerikesa_spiI, hdr->registerikesa_spiR);
}

void handleIKESAKeyRequestPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // ��ȡpayload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);

    // ���ι���KeyRequestPacket
    IKESAKeyRequestPacket pkt2(std::move(pkt1));
    ikesakeyrequesthdr *hdr = pkt2.getIKESAKeyRequestHdrPtr();
    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received IKECSAKEYREQUEST packet: "
                  << " spiI: " << std::hex << std::setw(16) << ntohl(hdr->keyreq_spiI) << std::dec // �ָ�ʮ���Ƹ�ʽ
                  << " spiR: " << std::hex << std::setw(16) << ntohl(hdr->keyreq_spiR) << std::dec // �ָ�ʮ���Ƹ�ʽ
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
        // ��ӡ��Կ
        for (uint8_t byte : getkeyvalue)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl; // �ָ�ʮ���Ƹ�ʽ
    }
    // ������Կ
    IKESAKeyRequestPacket pkt3;
    pkt3.ConstructIKESAkeyReturnPacket(hdr->keyreq_spiI, hdr->keyreq_spiR, hdr->keyreq_seq, hdr->keyreq_reqlen, getkeyvalue);
    send(fd, pkt3.getBufferPtr(), pkt3.getBufferSize(), 0);
}

void handleDestroyIKESAPacket(int fd, PacketBase &pkt1)
{
    uint16_t length;
    std::memcpy(&length, pkt1.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));
    // ��ȡpayload
    read(fd, pkt1.getBufferPtr() + BASE_HEADER_SIZE, length);
    pkt1.setBufferSize(BASE_HEADER_SIZE + length);
    // ���ι���DestoryPacket
    RegisterIKESAPacket pkt2(std::move(pkt1));
    registerikesahdr *hdr = pkt2.getRegisterIKESAPacketHeaderPtr();
    if (DEBUG_LEVEL == 1)
    {
        std::cout << "Received DestoryIKESA packet: "
                  << " source_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_source))
                  << " dest_ip: " << uint32ToIpString(ntohl(hdr->registerikesa_destination))
                  << " spiI: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiI) << std::dec // �ָ�ʮ���Ƹ�ʽ
                  << " spiR: " << std::hex << std::setw(16) << ntohl(hdr->registerikesa_spiR) << std::dec // �ָ�ʮ���Ƹ�ʽ
                  << std::endl;
    }
    globalSAManager.destoryIKESA(hdr->registerikesa_spiI, hdr->registerikesa_spiR);
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