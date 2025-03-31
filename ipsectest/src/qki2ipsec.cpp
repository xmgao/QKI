#include "qki2ipsecapi.hpp"

static int connectToServer(const std::string &ipAddress, int port)
{
    // 创建套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    // 设置服务器地址
    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // 转换IP地址
    if (inet_pton(AF_INET, ipAddress.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address/Address not supported" << std::endl;
        close(sockfd);
        return -1;
    }

    // 发起连接
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Connection Failed" << std::endl;
        close(sockfd);
        return -1;
    }

    // 返回文件描述符
    return sockfd;
}

bool my_qki_qpi::connectQKI(int &conn_QKI_fd, const std::string &QKI_IP_ADDRESS, int QKI_LISTEN_PORT)
{
    const int max_retries = 10; // 设置最大重试次数
    int retries = 0;

    while (conn_QKI_fd <= 0 && retries < max_retries)
    {
        conn_QKI_fd = connectToServer(QKI_IP_ADDRESS, QKI_LISTEN_PORT);
        if (conn_QKI_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            sleep(2); // 等待2秒
            retries++;
        }
    }
    // 检查连接状态并处理失败情况
    if (conn_QKI_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        // 在这里添加处理逻辑，比如返回特定错误码或抛出异常
        return false;
    }

    // 如果成功，继续处理连接
    return true;
}

void my_qki_qpi::openIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR)
{
    // 打开会话
    RegisterIKESAPacket pkt1;
    pkt1.ConstructRegisterIKESAPacket(srcip, dstip, spiI, spiR);
    send(conn_QKI_fd, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
}

bool my_qki_qpi::getIKESAkey(const int conn_QKI_fd, const uint64_t spiI, const uint64_t spiR,
                             uint32_t request_id, uint16_t request_len, uint32_t &qkey_id, std::vector<uint8_t> &qkeybuffer)
{
    // 构造IKESAKeyRequestPacket
    IKESAKeyRequestPacket pkt2;
    pkt2.ConstructIKESAkeyRequestPacket(spiI, spiR, request_id, request_len);

    // 发送请求
    if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
    {
        std::cerr << "Failed to send packet" << std::endl;
        close(conn_QKI_fd);
        return false;
    }

    // 处理密钥返回
    PacketBase pkt3;

    // 读取packet header
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

    // 读取payload
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
        // 带参构造KeyRequestPacket
        IKESAKeyRequestPacket pkt4(std::move(pkt3));
        qkey_id = pkt4.getIKESAKeyRequestHdrPtr()->keyreq_seq; // 获取qkey_id
        qkeybuffer.resize(request_len);
        std::memcpy(&qkeybuffer[0], pkt4.getKeyBufferPtr(), request_len);
        return true;
    }
    else
    {
        std::cerr << "Error: Get QKEY Failed." << std::endl;
    }
    return false; // 防止编译器警告
}

void my_qki_qpi::closeIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR)
{
    // 关闭IKE SA
    RegisterIKESAPacket pkt;
    pkt.ConstructDestoryIKESAPacket(srcip, dstip, spiI, spiR);
    send(conn_QKI_fd, pkt.getBufferPtr(), pkt.getBufferSize(), 0);
}

bool my_qki_qpi::closeQKI(int &conn_QKI_fd)
{
    // 检查文件描述符是否有效
    if (conn_QKI_fd == -1)
    {
        std::cerr << "Error: Invalid file descriptor." << std::endl;
        return false;
    }

    // 关闭 QKI 连接
    if (close(conn_QKI_fd) == -1)
    {
        std::cerr << "Error: Failed to close the connection." << std::endl;
        return false;
    }

    // 将文件描述符重置为 -1，表示连接已关闭
    conn_QKI_fd = -1;
    return true;
}

void my_qki_qpi::openIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                                    const uint32_t spi, bool is_inbound, bool is_otpalg)
{
    // 打开IPSec SA会话
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

    // 处理密钥返回
    PacketBase pkt3;

    // 读取packet header
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

    // 读取payload
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
        // 带参构造KeyRequestPacket
        IPSECSAKeyRequestPacket pkt4(std::move(pkt3));
        qkey_id = pkt4.getKeyRequestHeaderPtr()->keyreq_seq; // 获取qkey_id
        qkeybuffer.resize(request_len);
        std::memcpy(&qkeybuffer[0], pkt4.getKeyBufferPtr(), request_len);
        return true;
    }
    else
    {
        std::cerr << "Error: Get QKEY Failed." << std::endl;
    }
    return false; // 防止编译器警告
}

void my_qki_qpi::closeIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                                     const uint32_t spi, bool is_inbound, bool is_otpalg)
{
    // 关闭IPSECSA
    RegisterIPSECSAPacket closepkt2;
    closepkt2.ConstructDestoryIPSECSAPacket(IPPROACTIVE, IPPASSIVE, spi, is_inbound, is_otpalg);
    send(conn_QKI_fd, closepkt2.getBufferPtr(), closepkt2.getBufferSize(), 0);
}