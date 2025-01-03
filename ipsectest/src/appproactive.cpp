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

const int QKI_LISTEN_PORT = 50001; // QKI�����˿�
const int APP_LISTEN_PORT = 50002; // APP�����˿�
const std::string QKI_IP_ADDRESS = "127.0.0.1";

uint32_t spi_i = 5873;
uint32_t spi_o = 7546;
// 192.168.8.154 A  ====  192.168.8.182 B

std::string proactiveAPP_ipAddress;
std::string passiveAPP_ipAddress;

int connectToServer(const std::string &ipAddress, int port)
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
        perror("Connection Failed");
        close(sockfd);
        return -1;
    }

    // �����ļ�������
    return sockfd;
}

std::string uint32ToIpString(uint32_t ipNumeric)
{
    struct in_addr addr;
    addr.s_addr = htonl(ipNumeric); // �������ֽ���ת��Ϊ�����ֽ���

    char ipString[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN���㹻�洢IPv4��ַ���ַ�������
    if (inet_ntop(AF_INET, &addr, ipString, INET_ADDRSTRLEN) == nullptr)
    {
        // ������
        std::cerr << "Conversion failed." << std::endl;
        return "";
    }
    return std::string(ipString);
}

// ��IP��ַ�ַ���ת��Ϊuint32_t
uint32_t IpStringTouint32(const std::string &ipString)
{
    struct in_addr addr;
    // ���ַ�����ʽ��IPת��Ϊ�����ֽ���Ķ����Ƹ�ʽ
    if (inet_pton(AF_INET, ipString.c_str(), &addr) != 1)
    {
        // ������
        std::cerr << "Conversion failed." << std::endl;
        return 0;
    }
    // �������ֽ���ת��Ϊ�����ֽ���
    return ntohl(addr.s_addr);
}

// �����̺߳���
void EncthreadFunction()
{

    const int max_retries = 100; // ����������Դ���
    int retries = 0;
    int conn_PassiveAPP_fd = -1;

    // ���ӱ�����APP
    while (conn_PassiveAPP_fd <= 0 && retries < max_retries)
    {
        conn_PassiveAPP_fd = connectToServer(passiveAPP_ipAddress, APP_LISTEN_PORT);
        if (conn_PassiveAPP_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2)); // �ȴ�2��
            retries++;
        }
    }
    // �������״̬������ʧ�����
    if (conn_PassiveAPP_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        // ��������Ӵ����߼������緵���ض���������׳��쳣
        return;
    }

    // ����ɹ���������������
    std::cout << "Connected successfully!" << std::endl;

    // �������ݰ�
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

    // �����Ĵ����߼�
    uint32_t request_id = 1;
    uint32_t request_len = 128;
    // �������ݴ���
    while (request_id <= 30)
    {
    label3: // ��ǩ��������������Կ
        IPSECSAKeyRequestPacket pkt2;
        pkt2.ConstructIPSECSAkeyRequestPacket(spi_o, request_id, request_len);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return;
        }

        // ������Կ����
        PacketBase pkt3;

        // ��ȡpacket header
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

        // ��ȡpayload
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
            // ���ι���KeyRequestPacket
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
        // ��������
        std::string plaintext = "This is the data to be encrypted by SPI_OUT:" + std::to_string(spi_o) + " seq:" + std::to_string(request_id);
        std::string ciphertext;
        if (Encryptor::encrypt(plaintext, getkeyvalue, ciphertext))
        {
            std::cout << "Ciphertext: ";
            for (const auto &ch : ciphertext)
            {
                std::cout << std::hex << (int)ch << " ";
            }
            std::cout << std::dec << std::endl; // �ָ�ʮ���Ƹ�ʽ
        }
        else
        {
            std::cerr << "Encryption failed due to insufficient key length." << std::endl;
        }
        // ���͵��ն�APP
        if (send(conn_PassiveAPP_fd, &ciphertext[0], ciphertext.length(), 0) == -1)
        {
            perror("send Error");
            close(conn_PassiveAPP_fd);
            return;
        }
        // ��������ID����ֹ�ظ�ʹ����ͬ����Կ
        request_id++;
        // Sleep �������߼�
        sleep(1); // ���ú��ʵ�ʱ����
    }
    close(conn_PassiveAPP_fd);

    // �ر�IPSECSA
    RegisterIPSECSAPacket closepkt2;
    closepkt2.ConstructDestoryIPSECSAPacket(IPPROACTIVE, IPPASSIVE, spi_o, false,true);
    send(conn_QKI_fd, closepkt2.getBufferPtr(), closepkt2.getBufferSize(), 0);
}

// �����̺߳���
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

    // ����������APP����
    struct sockaddr_in st_sersock;
    int conn_Listen_fd = -1;

    if ((conn_Listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // ����socket�׽���
    {
        printf("socket Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    memset(&st_sersock, 0, sizeof(st_sersock));
    st_sersock.sin_family = AF_INET;
    st_sersock.sin_addr.s_addr = htonl(INADDR_ANY); // ����������
    st_sersock.sin_port = htons(APP_LISTEN_PORT);

    int opt = 1;
    // ���ö˿ڸ���	(����˿ڱ�ռ�õ�����)
    if (setsockopt(conn_Listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) // ���ö˿ڸ���	(����˿ڱ�ռ�õ�����)
    {
        printf("setsockopt Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    if (bind(conn_Listen_fd, (struct sockaddr *)&st_sersock, sizeof(st_sersock)) < 0) // ���׽��ְ�IP�Ͷ˿����ڼ���
    {
        printf("bind Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    if (listen(conn_Listen_fd, 20) < 0) // �趨��ͬʱ�ŶӵĿͻ���������Ӹ���
    {
        printf("listen Error: %s (errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    printf("======waiting for client's request======\n");
    // ׼������������APP����
    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int conn_passive_APP_fd = accept(conn_Listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (conn_passive_APP_fd < 0)
    {
        perror("accept");
        return;
    }

    // ���ӳɹ����������ѭ��
    uint32_t request_len = 128;
    uint32_t request_id = 1;
    while (request_id <= 30)
    {
        // ��ȡ������APP�������ݰ�
        char buffer[512];
        ssize_t bytes_read = read(conn_passive_APP_fd, buffer, sizeof(buffer));
        if (bytes_read <= 0)
        {
            perror("read Error");
            close(conn_passive_APP_fd);
            return;
        }
        // ������������ת��Ϊ std::string��ȷ��ֻʹ�ö�ȡ���ֽ���
        std::string ciphertext(buffer, bytes_read);

        std::string decryptedtext;

    label4: // ��ǩ��������������Կ

        IPSECSAKeyRequestPacket pkt2;
        pkt2.ConstructIPSECSAkeyRequestPacket(spi_i, request_id, request_len);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return;
        }

        // ������Կ����
        PacketBase pkt3;

        // ��ȡpacket header
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

        // ��ȡpayload
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
            // ���ι���KeyRequestPacket
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

        // ����
        if (Encryptor::decrypt(ciphertext, getkeyvalue, decryptedtext))
        {
            std::cout << "Decrypted text: " << decryptedtext << std::endl;
            for (const auto &ch : ciphertext)
            {
                std::cout << std::hex << (int)ch << " ";
            }
            std::cout << std::dec << std::endl; // �ָ�ʮ���Ƹ�ʽ
        }
        else
        {
            std::cerr << "Decryption failed due to insufficient key length." << std::endl;
        }

        // ��������ID����ֹ�ظ�ʹ����ͬ����Կ
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
    // ����QKI
    int conn_QKI_fd = -1;

    const int max_retries = 100; // ����������Դ���
    int retries = 0;

    while (conn_QKI_fd <= 0 && retries < max_retries)
    {
        conn_QKI_fd = connectToServer(QKI_IP_ADDRESS, QKI_LISTEN_PORT);
        if (conn_QKI_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2)); // �ȴ�2��
            retries++;
        }
    }
    // �������״̬������ʧ�����
    if (conn_QKI_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        // ��������Ӵ����߼������緵���ض���������׳��쳣
        return 0;
    }

    // ����ɹ���������������
    std::cout << "Connected successfully!" << std::endl;
    // �����Ĵ����߼�

    // �򿪻Ự
    RegisterIKESAPacket pkt1;
    uint32_t sourceip = htonl(IpStringTouint32(proactiveAPP_ipAddress));
    uint32_t desip = htonl(IpStringTouint32(passiveAPP_ipAddress));
    uint64_t spiI = 5344634845;
    uint64_t spiR = 9875983014;
    pkt1.ConstructRegisterIKESAPacket(sourceip, desip, spiI, spiR);
    send(conn_QKI_fd, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
    int request_len = 32;
    // ����DH��Կ�滻
    {
    label1: // ��ǩ��������������Կ
        IKESAKeyRequestPacket pkt2;
        pkt2.ConstructIKESAkeyRequestPacket(spiI, spiR, 1, 32);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return 0;
        }
        // ������Կ����
        PacketBase pkt3;

        // ��ȡpacket header
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

        // ��ȡpayload
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
            // ���ι���KeyRequestPacket
            IKESAKeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
            {
                std::cout << "GET_DH_KEY: ";
                for (const auto &ch : getkeyvalue)
                {
                    std::cout << std::hex << (int)ch << " ";
                }
                std::cout << std::dec << std::endl; // �ָ�ʮ���Ƹ�ʽ
            }
        }
        else
        {
            perror("getDHkey Error");
            sleep(1);
            goto label1;
        }
    }

    // ����PSK��Կ�滻
    {
    label2: // ��ǩ��������������Կ
        IKESAKeyRequestPacket pkt2;
        pkt2.ConstructIKESAkeyRequestPacket(spiI, spiR, 2, 32);
        if (send(conn_QKI_fd, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(conn_QKI_fd);
            return 0;
        }
        // ������Կ����
        PacketBase pkt3;

        // ��ȡpacket header
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

        // ��ȡpayload
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
            // ���ι���KeyRequestPacket
            IKESAKeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
            {
                std::cout << "GET_PSK_KEY: ";
                for (const auto &ch : getkeyvalue)
                {
                    std::cout << std::hex << (int)ch << " ";
                }
                std::cout << std::dec << std::endl; // �ָ�ʮ���Ƹ�ʽ
            }
        }
        else
        {
            perror("getPSKkey Error");
            sleep(1);
            goto label2;
        }
    }

    // ���������̲߳����ݲ���
    std::thread t1(EncthreadFunction);
    std::thread t2(DecthreadFunction);

    // �ȴ��߳�t���
    t1.join();
    t2.join();

    // �ر�IKE SA
    RegisterIKESAPacket despkt;
    despkt.ConstructDestoryIKESAPacket(sourceip, desip, spiI, spiR);
    send(conn_QKI_fd, despkt.getBufferPtr(), despkt.getBufferSize(), 0);
    close(conn_QKI_fd);
}
