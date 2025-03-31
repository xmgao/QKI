#include "qki2ipsecapi.hpp"

static int connectToServer(const std::string &ipAddress, int port)
{
    // �����׽���
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    // ���÷�������ַ
    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // ת��IP��ַ
    if (inet_pton(AF_INET, ipAddress.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address/Address not supported" << std::endl;
        close(sockfd);
        return -1;
    }

    // ��������
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Connection Failed" << std::endl;
        close(sockfd);
        return -1;
    }

    // �����ļ�������
    return sockfd;
}

bool my_qki_qpi::connectQKI(int &conn_QKI_fd, const std::string &QKI_IP_ADDRESS, int QKI_LISTEN_PORT)
{
    const int max_retries = 10; // ����������Դ���
    int retries = 0;

    while (conn_QKI_fd <= 0 && retries < max_retries)
    {
        conn_QKI_fd = connectToServer(QKI_IP_ADDRESS, QKI_LISTEN_PORT);
        if (conn_QKI_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            sleep(2); // �ȴ�2��
            retries++;
        }
    }
    // �������״̬������ʧ�����
    if (conn_QKI_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        // ��������Ӵ����߼������緵���ض���������׳��쳣
        return false;
    }

    // ����ɹ���������������
    return true;
}

void my_qki_qpi::openIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR)
{
    // �򿪻Ự
    RegisterIKESAPacket pkt1;
    pkt1.ConstructRegisterIKESAPacket(srcip, dstip, spiI, spiR);
    send(conn_QKI_fd, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
}

bool my_qki_qpi::getIKESAkey(const int conn_QKI_fd, const uint64_t spiI, const uint64_t spiR,
                             uint32_t request_id, uint16_t request_len, uint32_t &qkey_id, std::vector<uint8_t> &qkeybuffer)
{
    // ����IKESAKeyRequestPacket
    IKESAKeyRequestPacket pkt2;
    pkt2.ConstructIKESAkeyRequestPacket(spiI, spiR, request_id, request_len);

    // ��������
    if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
    {
        std::cerr << "Failed to send packet" << std::endl;
        close(conn_QKI_fd);
        return false;
    }

    // ������Կ����
    PacketBase pkt3;

    // ��ȡpacket header
    ssize_t bytes_read = read(conn_QKI_fd, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
    if (bytes_read <= 0)
    {
        std::cerr << "Error reading packet header" << std::endl;
        close(conn_QKI_fd);
        return false;
    }

    uint16_t value1, length;
    std::memcpy(&value1, pkt3.getBufferPtr(), sizeof(uint16_t));
    std::memcpy(&length, pkt3.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

    // ��ȡpayload
    bytes_read = read(conn_QKI_fd, pkt3.getBufferPtr() + BASE_HEADER_SIZE, length);
    if (bytes_read != length)
    {
        std::cerr << "Error reading payload" << std::endl;
        close(conn_QKI_fd);
        return false;
    }

    pkt3.setBufferSize(BASE_HEADER_SIZE + length);

    if (value1 == static_cast<uint16_t>(PacketType::GETKEYRETURNIKESA))
    {
        // ���ι���KeyRequestPacket
        IKESAKeyRequestPacket pkt4(std::move(pkt3));
        qkey_id = pkt4.getIKESAKeyRequestHdrPtr()->keyreq_seq; // ��ȡqkey_id
        qkeybuffer.resize(request_len);
        std::memcpy(&qkeybuffer[0], pkt4.getKeyBufferPtr(), request_len);
        return true;
    }
    else
    {
        std::cerr << "Error: Get QKEY Failed." << std::endl;
    }
    return false; // ��ֹ����������
}

void my_qki_qpi::closeIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR)
{
    // �ر�IKE SA
    RegisterIKESAPacket pkt;
    pkt.ConstructDestoryIKESAPacket(srcip, dstip, spiI, spiR);
    send(conn_QKI_fd, pkt.getBufferPtr(), pkt.getBufferSize(), 0);
}

bool my_qki_qpi::closeQKI(int &conn_QKI_fd)
{
    // ����ļ��������Ƿ���Ч
    if (conn_QKI_fd == -1)
    {
        std::cerr << "Error: Invalid file descriptor." << std::endl;
        return false;
    }

    // �ر� QKI ����
    if (close(conn_QKI_fd) == -1)
    {
        std::cerr << "Error: Failed to close the connection." << std::endl;
        return false;
    }

    // ���ļ�����������Ϊ -1����ʾ�����ѹر�
    conn_QKI_fd = -1;
    return true;
}

void my_qki_qpi::openIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                                    const uint32_t spi, bool is_inbound, bool is_otpalg)
{
    // ��IPSec SA�Ự
    RegisterIPSECSAPacket ipsecsa2pkt;
    ipsecsa2pkt.ConstructRegisterIPSECSAPacket(IPPROACTIVE, IPPASSIVE, spi, false, true);
    send(conn_QKI_fd, ipsecsa2pkt.getBufferPtr(), ipsecsa2pkt.getBufferSize(), 0);
}

bool my_qki_qpi::getIPecSAkey(const int conn_QKI_fd, uint32_t spi,
                              uint32_t request_id, uint16_t request_len, uint32_t &qkey_id, std::vector<uint8_t> &qkeybuffer)
{
    IPSECSAKeyRequestPacket pkt2;
    pkt2.ConstructIPSECSAkeyRequestPacket(spi, request_id, request_len);
    if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
    {
        std::cerr << "Failed to send packet" << std::endl;
        close(conn_QKI_fd);
        return false;
    }

    // ������Կ����
    PacketBase pkt3;

    // ��ȡpacket header
    ssize_t bytes_read2 = read(conn_QKI_fd, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
    if (bytes_read2 <= 0)
    {
        std::cerr << "Error reading packet header" << std::endl;
        close(conn_QKI_fd);
        return false;
    }

    uint16_t value1, length;
    std::memcpy(&value1, pkt3.getBufferPtr(), sizeof(uint16_t));
    std::memcpy(&length, pkt3.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

    // ��ȡpayload
    bytes_read2 = read(conn_QKI_fd, pkt3.getBufferPtr() + BASE_HEADER_SIZE, length);
    if (bytes_read2 != length)
    {
        std::cerr << "Error reading payload" << std::endl;
        close(conn_QKI_fd);
        return false;
    }

    pkt3.setBufferSize(BASE_HEADER_SIZE + length);

    if (value1 == static_cast<uint16_t>(PacketType::GETKEYRETURNIPSECSA))
    {
        // ���ι���KeyRequestPacket
        IPSECSAKeyRequestPacket pkt4(std::move(pkt3));
        qkey_id = pkt4.getKeyRequestHeaderPtr()->keyreq_seq; // ��ȡqkey_id
        qkeybuffer.resize(request_len);
        std::memcpy(&qkeybuffer[0], pkt4.getKeyBufferPtr(), request_len);
        return true;
    }
    else
    {
        std::cerr << "Error: Get QKEY Failed." << std::endl;
    }
    return false; // ��ֹ����������
}

void my_qki_qpi::closeIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                                     const uint32_t spi, bool is_inbound, bool is_otpalg)
{
    // �ر�IPSECSA
    RegisterIPSECSAPacket closepkt2;
    closepkt2.ConstructDestoryIPSECSAPacket(IPPROACTIVE, IPPASSIVE, spi, is_inbound, is_otpalg);
    send(conn_QKI_fd, closepkt2.getBufferPtr(), closepkt2.getBufferSize(), 0);
}