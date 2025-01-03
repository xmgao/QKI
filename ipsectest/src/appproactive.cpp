#include "packets.hpp"
#include "Encryptor.hpp"

#include <sys/epoll.h>
#include <netinet/in.h>
#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> // for close()
#include <thread>
#include <chrono>

//./appproactive 192.168.8.184 192.168.8.126

const int QKI_LISTEN_PORT = 50001; // QKI监听端口
const int APP_LISTEN_PORT = 50002; // APP监听端口
const std::string QKI_IP_ADDRESS = "127.0.0.1";

uint32_t spi_i = 5873;
uint32_t spi_o = 7546;
// 192.168.8.154 A  ====  192.168.8.182 B

std::string proactiveAPP_ipAddress;
std::string passiveAPP_ipAddress;

int connectToServer(const std::string &ipAddress, int port)
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
        perror("Connection Failed");
        close(sockfd);
        return -1;
    }

    // 返回文件描述符
    return sockfd;
}

std::string uint32ToIpString(uint32_t ipNumeric)
{
    struct in_addr addr;
    addr.s_addr = htonl(ipNumeric); // 将主机字节序转换为网络字节序

    char ipString[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN是足够存储IPv4地址的字符串长度
    if (inet_ntop(AF_INET, &addr, ipString, INET_ADDRSTRLEN) == nullptr)
    {
        // 错误处理
        std::cerr << "Conversion failed." << std::endl;
        return "";
    }
    return std::string(ipString);
}

// 将IP地址字符串转换为uint32_t
uint32_t IpStringTouint32(const std::string &ipString)
{
    struct in_addr addr;
    // 将字符串形式的IP转换为网络字节序的二进制格式
    if (inet_pton(AF_INET, ipString.c_str(), &addr) != 1)
    {
        // 错误处理
        std::cerr << "Conversion failed." << std::endl;
        return 0;
    }
    // 将网络字节序转换为主机字节序
    return ntohl(addr.s_addr);
}

// 加密线程函数
void EncthreadFunction()
{

    const int max_retries = 100; // 设置最大重试次数
    int retries = 0;
    int conn_PassiveAPP_fd = -1;

    // 连接被动端APP
    while (conn_PassiveAPP_fd <= 0 && retries < max_retries)
    {
        conn_PassiveAPP_fd = connectToServer(passiveAPP_ipAddress, APP_LISTEN_PORT);
        if (conn_PassiveAPP_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2)); // 等待2秒
            retries++;
        }
    }
    // 检查连接状态并处理失败情况
    if (conn_PassiveAPP_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        // 在这里添加处理逻辑，比如返回特定错误码或抛出异常
        return;
    }

    // 如果成功，继续处理连接
    std::cout << "Connected successfully!" << std::endl;

    // 发送数据包
    uint32_t IPPROACTIVE = htonl(IpStringTouint32(proactiveAPP_ipAddress));
    uint32_t IPPASSIVE = htonl(IpStringTouint32(passiveAPP_ipAddress));

    int conn_QKI_fd = connectToServer(QKI_IP_ADDRESS, QKI_LISTEN_PORT);
    if (conn_QKI_fd <= 0)
    {
        std::cout << "Failed to connect QKI" << std::endl;
    }
    RegisterIPSECSAPacket ipsecsa2pkt;
    ipsecsa2pkt.ConstructRegisterIPSECSAPacket(IPPROACTIVE, IPPASSIVE, spi_o, false, true);
    send(conn_QKI_fd, ipsecsa2pkt.getBufferPtr(), ipsecsa2pkt.getBufferSize(), 0);

    // 后续的处理逻辑
    uint32_t request_id = 1;
    uint32_t request_len = 128;
    // 加密数据传输
    while (request_id <= 30)
    {
    label3: // 标签用于重新请求密钥
        IPSECSAKeyRequestPacket pkt2;
        pkt2.ConstructIPSECSAkeyRequestPacket(spi_o, request_id, request_len);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return;
        }

        // 处理密钥返回
        PacketBase pkt3;

        // 读取packet header
        ssize_t bytes_read2 = read(conn_QKI_fd, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
        if (bytes_read2 <= 0)
        {
            perror("read Error");
            close(conn_QKI_fd);
            return;
        }

        uint16_t value1, length;
        std::memcpy(&value1, pkt3.getBufferPtr(), sizeof(uint16_t));
        std::memcpy(&length, pkt3.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

        // 读取payload
        bytes_read2 = read(conn_QKI_fd, pkt3.getBufferPtr() + BASE_HEADER_SIZE, length);
        if (bytes_read2 != length)
        {
            perror("Incomplete payload read");
            close(conn_QKI_fd);
            return;
        }

        pkt3.setBufferSize(BASE_HEADER_SIZE + length);
        std::string getkeyvalue;
        if (value1 == static_cast<uint16_t>(PacketType::GETKEYRETURNIPSECSA))
        {
            // 带参构造KeyRequestPacket
            IPSECSAKeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
        }
        else
        {
            perror("getkey Error");
            sleep(1);
            goto label3;
        }
        // 加密数据
        std::string plaintext = "This is the data to be encrypted by SPI_OUT:" + std::to_string(spi_o) + " seq:" + std::to_string(request_id);
        std::string ciphertext;
        if (Encryptor::encrypt(plaintext, getkeyvalue, ciphertext))
        {
            std::cout << "Ciphertext: ";
            for (const auto &ch : ciphertext)
            {
                std::cout << std::hex << (int)ch << " ";
            }
            std::cout << std::dec << std::endl; // 恢复十进制格式
        }
        else
        {
            std::cerr << "Encryption failed due to insufficient key length." << std::endl;
        }
        // 发送到终端APP
        if (send(conn_PassiveAPP_fd, &ciphertext[0], ciphertext.length(), 0) == -1)
        {
            perror("send Error");
            close(conn_PassiveAPP_fd);
            return;
        }
        // 增加请求ID，防止重复使用相同的密钥
        request_id++;
        // Sleep 或其他逻辑
        sleep(1); // 设置合适的时间间隔
    }
    close(conn_PassiveAPP_fd);

    // 关闭IPSECSA
    RegisterIPSECSAPacket closepkt2;
    closepkt2.ConstructDestoryIPSECSAPacket(IPPROACTIVE, IPPASSIVE, spi_o, false,true);
    send(conn_QKI_fd, closepkt2.getBufferPtr(), closepkt2.getBufferSize(), 0);
}

// 解密线程函数
void DecthreadFunction()
{

    uint32_t IPPROACTIVE = htonl(IpStringTouint32(proactiveAPP_ipAddress));
    uint32_t IPPASSIVE = htonl(IpStringTouint32(passiveAPP_ipAddress));

    int conn_QKI_fd = connectToServer(QKI_IP_ADDRESS, QKI_LISTEN_PORT);
    if (conn_QKI_fd <= 0)
    {
        std::cout << "Failed to connect QKI" << std::endl;
    }
    RegisterIPSECSAPacket ipsecsa1pkt;
    ipsecsa1pkt.ConstructRegisterIPSECSAPacket(IPPASSIVE, IPPROACTIVE, spi_i, true,true);
    send(conn_QKI_fd, ipsecsa1pkt.getBufferPtr(), ipsecsa1pkt.getBufferSize(), 0);

    // 监听被动端APP连接
    struct sockaddr_in st_sersock;
    int conn_Listen_fd = -1;

    if ((conn_Listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // 建立socket套接字
    {
        printf("socket Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    memset(&st_sersock, 0, sizeof(st_sersock));
    st_sersock.sin_family = AF_INET;
    st_sersock.sin_addr.s_addr = htonl(INADDR_ANY); // 监听主动端
    st_sersock.sin_port = htons(APP_LISTEN_PORT);

    int opt = 1;
    // 设置端口复用	(解决端口被占用的问题)
    if (setsockopt(conn_Listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) // 设置端口复用	(解决端口被占用的问题)
    {
        printf("setsockopt Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    if (bind(conn_Listen_fd, (struct sockaddr *)&st_sersock, sizeof(st_sersock)) < 0) // 将套接字绑定IP和端口用于监听
    {
        printf("bind Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    if (listen(conn_Listen_fd, 20) < 0) // 设定可同时排队的客户端最大连接个数
    {
        printf("listen Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    printf("======waiting for client's request======\n");
    // 准备接受主动端APP连接
    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int conn_passive_APP_fd = accept(conn_Listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (conn_passive_APP_fd < 0)
    {
        perror("accept");
        return;
    }

    // 连接成功，进入解密循环
    uint32_t request_len = 128;
    uint32_t request_id = 1;
    while (request_id <= 30)
    {
        // 读取主动端APP加密数据包
        char buffer[512];
        ssize_t bytes_read = read(conn_passive_APP_fd, buffer, sizeof(buffer));
        if (bytes_read <= 0)
        {
            perror("read Error");
            close(conn_passive_APP_fd);
            return;
        }
        // 将缓冲区内容转换为 std::string，确保只使用读取的字节数
        std::string ciphertext(buffer, bytes_read);

        std::string decryptedtext;

    label4: // 标签用于重新请求密钥

        IPSECSAKeyRequestPacket pkt2;
        pkt2.ConstructIPSECSAkeyRequestPacket(spi_i, request_id, request_len);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return;
        }

        // 处理密钥返回
        PacketBase pkt3;

        // 读取packet header
        ssize_t bytes_read2 = read(conn_QKI_fd, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
        if (bytes_read2 <= 0)
        {
            perror("read Error");
            close(conn_QKI_fd);
            return;
        }

        uint16_t value1, length;
        std::memcpy(&value1, pkt3.getBufferPtr(), sizeof(uint16_t));
        std::memcpy(&length, pkt3.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

        // 读取payload
        bytes_read2 = read(conn_QKI_fd, pkt3.getBufferPtr() + BASE_HEADER_SIZE, length);
        if (bytes_read2 != length)
        {
            perror("Incomplete payload read");
            close(conn_QKI_fd);
            return;
        }

        pkt3.setBufferSize(BASE_HEADER_SIZE + length);
        std::string getkeyvalue;
        if (value1 == static_cast<uint16_t>(PacketType::GETKEYRETURNIPSECSA))
        {
            // 带参构造KeyRequestPacket
            IPSECSAKeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
        }
        else
        {
            perror("getkey Error");
            sleep(1);
            goto label4;
        }

        // 解密
        if (Encryptor::decrypt(ciphertext, getkeyvalue, decryptedtext))
        {
            std::cout << "Decrypted text: " << decryptedtext << std::endl;
            for (const auto &ch : ciphertext)
            {
                std::cout << std::hex << (int)ch << " ";
            }
            std::cout << std::dec << std::endl; // 恢复十进制格式
        }
        else
        {
            std::cerr << "Decryption failed due to insufficient key length." << std::endl;
        }

        // 增加请求ID，防止重复使用相同的密钥
        request_id++;
    }
    close(conn_passive_APP_fd);
    RegisterIPSECSAPacket closepkt1;
    closepkt1.ConstructDestoryIPSECSAPacket(IPPASSIVE, IPPROACTIVE, spi_i, true,true);
    send(conn_QKI_fd, closepkt1.getBufferPtr(), closepkt1.getBufferSize(), 0);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <ipsec_initiator_IP_address> <ipsec_responser_IP_address>" << std::endl;
        return 1;
    }

    proactiveAPP_ipAddress = argv[1];
    passiveAPP_ipAddress = argv[2];
    // 连接QKI
    int conn_QKI_fd = -1;

    const int max_retries = 100; // 设置最大重试次数
    int retries = 0;

    while (conn_QKI_fd <= 0 && retries < max_retries)
    {
        conn_QKI_fd = connectToServer(QKI_IP_ADDRESS, QKI_LISTEN_PORT);
        if (conn_QKI_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2)); // 等待2秒
            retries++;
        }
    }
    // 检查连接状态并处理失败情况
    if (conn_QKI_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        // 在这里添加处理逻辑，比如返回特定错误码或抛出异常
        return 0;
    }

    // 如果成功，继续处理连接
    std::cout << "Connected successfully!" << std::endl;
    // 后续的处理逻辑

    // 打开会话
    RegisterIKESAPacket pkt1;
    uint32_t sourceip = htonl(IpStringTouint32(proactiveAPP_ipAddress));
    uint32_t desip = htonl(IpStringTouint32(passiveAPP_ipAddress));
    uint64_t spiI = 5344634845;
    uint64_t spiR = 9875983014;
    pkt1.ConstructRegisterIKESAPacket(sourceip, desip, spiI, spiR);
    send(conn_QKI_fd, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
    int request_len = 32;
    // 请求DH密钥替换
    {
    label1: // 标签用于重新请求密钥
        IKESAKeyRequestPacket pkt2;
        pkt2.ConstructIKESAkeyRequestPacket(spiI, spiR, 1, 32);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return 0;
        }
        // 处理密钥返回
        PacketBase pkt3;

        // 读取packet header
        ssize_t bytes_read = read(conn_QKI_fd, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
        if (bytes_read <= 0)
        {
            perror("read Error");
            close(conn_QKI_fd);
            return 0;
        }

        uint16_t value1, length;
        std::memcpy(&value1, pkt3.getBufferPtr(), sizeof(uint16_t));
        std::memcpy(&length, pkt3.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

        // 读取payload
        bytes_read = read(conn_QKI_fd, pkt3.getBufferPtr() + BASE_HEADER_SIZE, length);
        if (bytes_read != length)
        {
            perror("Incomplete payload read");
            close(conn_QKI_fd);
            return 0;
        }

        pkt3.setBufferSize(BASE_HEADER_SIZE + length);
        std::string getkeyvalue;
        if (value1 == static_cast<uint16_t>(PacketType::GETKEYRETURNIKESA))
        {
            // 带参构造KeyRequestPacket
            IKESAKeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
            {
                std::cout << "GET_DH_KEY: ";
                for (const auto &ch : getkeyvalue)
                {
                    std::cout << std::hex << (int)ch << " ";
                }
                std::cout << std::dec << std::endl; // 恢复十进制格式
            }
        }
        else
        {
            perror("getDHkey Error");
            sleep(1);
            goto label1;
        }
    }

    // 请求PSK密钥替换
    {
    label2: // 标签用于重新请求密钥
        IKESAKeyRequestPacket pkt2;
        pkt2.ConstructIKESAkeyRequestPacket(spiI, spiR, 2, 32);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return 0;
        }
        // 处理密钥返回
        PacketBase pkt3;

        // 读取packet header
        ssize_t bytes_read = read(conn_QKI_fd, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
        if (bytes_read <= 0)
        {
            perror("read Error");
            close(conn_QKI_fd);
            return 0;
        }

        uint16_t value1, length;
        std::memcpy(&value1, pkt3.getBufferPtr(), sizeof(uint16_t));
        std::memcpy(&length, pkt3.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

        // 读取payload
        bytes_read = read(conn_QKI_fd, pkt3.getBufferPtr() + BASE_HEADER_SIZE, length);
        if (bytes_read != length)
        {
            perror("Incomplete payload read");
            close(conn_QKI_fd);
            return 0;
        }

        pkt3.setBufferSize(BASE_HEADER_SIZE + length);
        std::string getkeyvalue;
        if (value1 == static_cast<uint16_t>(PacketType::GETKEYRETURNIKESA))
        {
            // 带参构造KeyRequestPacket
            IKESAKeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
            {
                std::cout << "GET_PSK_KEY: ";
                for (const auto &ch : getkeyvalue)
                {
                    std::cout << std::hex << (int)ch << " ";
                }
                std::cout << std::dec << std::endl; // 恢复十进制格式
            }
        }
        else
        {
            perror("getPSKkey Error");
            sleep(1);
            goto label2;
        }
    }

    // 创建两个线程并传递参数
    std::thread t1(EncthreadFunction);
    std::thread t2(DecthreadFunction);

    // 等待线程t完成
    t1.join();
    t2.join();

    // 关闭IKE SA
    RegisterIKESAPacket despkt;
    despkt.ConstructDestoryIKESAPacket(sourceip, desip, spiI, spiR);
    send(conn_QKI_fd, despkt.getBufferPtr(), despkt.getBufferSize(), 0);
    close(conn_QKI_fd);
}
