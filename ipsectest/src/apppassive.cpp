#include "Encryptor.hpp"
#include "qki2ipsecapi.hpp"
#include <thread>
//./apppassive 192.168.8.184 192.168.8.126

int QKI_LISTEN_PORT = 50001;       // QKI默认监听端口
const int APP_LISTEN_PORT = 50002; // APP监听端口
const std::string QKI_IP_ADDRESS = "127.0.0.1";

uint32_t spi_o = 22222222;
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
        std::cerr << "Connection Failed" << std::endl;
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

void test1()
{
    std::cout << "test1 begin!" << std::endl;

    // 连接QKI
    int conn_QKI_fd = -1;

    if (!my_qki_qpi::connectQKI(conn_QKI_fd, QKI_IP_ADDRESS, QKI_LISTEN_PORT))
    {
        std::cerr << "Failed to connect to QKI" << std::endl;
        return;
    }
    std::cout << "Connect QKI successfully" << std::endl;

    uint64_t spiI = 5344634845;
    uint64_t spiR = 9875983014;
    uint32_t sourceip = htonl(IpStringTouint32(proactiveAPP_ipAddress));
    uint32_t desip = htonl(IpStringTouint32(passiveAPP_ipAddress));

    // 注册IKE SA会话
    my_qki_qpi::openIKESAsession(conn_QKI_fd, sourceip, desip, spiI, spiR);
    std::cout << "open IKESA session with SPI:" << spiI << "_i\t" << spiR << "_r\t" << "successfully" << std::endl;

    int request_len = 32;
    std::vector<uint8_t> qkeybuffer(request_len);
    uint32_t qkey_id1 = 0; // 请求阶段1密钥替换
    // 请求阶段1密钥替换
    if (my_qki_qpi::getIKESAkey(conn_QKI_fd, spiI, spiR, 1, request_len, qkey_id1, qkeybuffer))
    {

        std::cout << "GET_QKEY with ID: " << qkey_id1 << "\t";
        for (const auto &ch : qkeybuffer)
        {
            std::cout << std::hex << (int)ch << " ";
        }
        std::cout << std::dec << std::endl; // 恢复十进制格式
    }
    std::vector<uint8_t> qkeybuffer2(request_len);
    uint32_t qkey_id2 = 0; // 请求阶段2密钥替换
    // 请求阶段2密钥替换
    if (my_qki_qpi::getIKESAkey(conn_QKI_fd, spiI, spiR, 2, request_len, qkey_id2, qkeybuffer2))
    {
        std::cout << "GET_QKEY with ID: " << qkey_id2 << "\t";
        for (const auto &ch : qkeybuffer2)
        {
            std::cout << std::hex << (int)ch << " ";
        }
        std::cout << std::dec << std::endl; // 恢复十进制格式
    }

    // 关闭IKE SA会话
    my_qki_qpi::closeIKESAsession(conn_QKI_fd, sourceip, desip, spiI, spiR);

    std::cout << "close IKESA session with SPI:" << spiI << "_i\t" << spiR << "_r\t" << "successfully" << std::endl;

    if (!my_qki_qpi::closeQKI(conn_QKI_fd))
    {
        std::cerr << "Failed to close QKI" << std::endl;
        return;
    }
    std::cout << "disConnect QKI successfully" << std::endl;
    std::cout << "test1 success!\n"
              << std::endl;
}

// 加密测试
void test2()
{

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

    // 如果成功，继续处理连接
    std::cout << "Connected successfully!" << std::endl;

    // 连接QKI
    int conn_QKI_fd = -1;

    if (!my_qki_qpi::connectQKI(conn_QKI_fd, QKI_IP_ADDRESS, QKI_LISTEN_PORT))
    {
        std::cerr << "Failed to connect to QKI" << std::endl;
        return;
    }
    std::cout << "Connect QKI successfully" << std::endl;

    uint32_t IPPROACTIVE = htonl(IpStringTouint32(proactiveAPP_ipAddress));
    uint32_t IPPASSIVE = htonl(IpStringTouint32(passiveAPP_ipAddress)); // 将IP地址转换为网络字节序

    my_qki_qpi::openIPSecSAsession(conn_QKI_fd, IPPROACTIVE, IPPASSIVE, spi_o, true, true);

    // 后续的处理逻辑
    uint32_t request_id = 1;
    uint32_t request_len = 128;
    // 解密数据传输
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

        std::vector<uint8_t> qkeybuffer(request_len);
        uint32_t qkey_id1 = 0; // 请求密钥
        if (my_qki_qpi::getIPecSAkey(conn_QKI_fd, spi_o, request_id, request_len, qkey_id1, qkeybuffer))
        {

            std::cout << "GET_QKEY with ID: " << qkey_id1 << "\t";
            for (const auto &ch : qkeybuffer)
            {
                std::cout << std::hex << (int)ch << " ";
            }
            std::cout << std::dec << std::endl; // 恢复十进制格式
        }

        std::string getkeyvalue(qkeybuffer.begin(), qkeybuffer.end());

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
        // Sleep 或其他逻辑
        sleep(1); // 设置合适的时间间隔
    }
    close(conn_passive_APP_fd); // 关闭主动端APP连接
    close(conn_Listen_fd);  // 关闭监听套接字
    my_qki_qpi::closeIPSecSAsession(conn_QKI_fd, IPPROACTIVE, IPPASSIVE, spi_o, true, true);

    if (!my_qki_qpi::closeQKI(conn_QKI_fd))
    {
        std::cerr << "Failed to close QKI" << std::endl;
        return;
    }
    std::cout << "disConnect QKI successfully" << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc == 3)
    {
        proactiveAPP_ipAddress = argv[1];
        passiveAPP_ipAddress = argv[2];
    }
    else if (argc == 4)
    {
        proactiveAPP_ipAddress = argv[1];
        passiveAPP_ipAddress = argv[2];
        QKI_LISTEN_PORT = atoi(argv[3]);
    }
    else
    {
        std::cerr << "Usage: " << argv[0] << " <ipsec_initiator_IP_address> <ipsec_responser_IP_address>  <QKI listen Port>" << std::endl;
        return 1;
    }
    // 测试IKE SA
    test1();
    // 测试IPSec SA，OTP密钥派生
    test2();

    return 0;
}
