#include "samanagement.hpp"
#include "debuglevel.hpp"
#include "handler.hpp"
#include "server.hpp"

extern MessageHandlerRegistry global_registry;

Server::Server(int port)
    : port_(port)
{
    listen_fd_ = createAndBindSocket(port_);
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0)
    {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    addToEpoll(epoll_fd_, listen_fd_);
}

Server::~Server()
{
    close(listen_fd_);
}

int Server::createAndBindSocket(int port)
{
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((uint16_t)port);

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(listen_sock, SOMAXCONN) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return listen_sock;
}

void addToEpoll(int epoll_fd, int fd)
{
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }
}

void Server::handleMessage(int fd)
{

    // 创建一个 PacketBase 对象
    PacketBase pkt1;

    // 读取packet header
    ssize_t bytes_read = read(fd, pkt1.getBufferPtr(), BASE_HEADER_SIZE);
    if (bytes_read < 0)
    {
        perror("read Error");
        close(fd);
    }
    else if (bytes_read == 0)
    {
        // 客户端关闭了连接
        std::cout << "Connection closed on socket: " << fd << std::endl;
        close(fd);
    }
    else
    {
        uint16_t typevalue;
        std::memcpy(&typevalue, pkt1.getBufferPtr(), sizeof(uint16_t));
        // 解析消息类型
        std::cout << "Server Received message! " << std::endl;
        PacketType type = parsePacketType(typevalue);
        // 获取并调用相应的回调函数
        MessageHandler handler = global_registry.getHandler(type);
        if (handler)
        {
            handler(fd, pkt1);
        }
        else
        {
            printf("No handler registered for message type %d\n", static_cast<uint16_t>(type));
            close(fd);
        }
    }
}

void Server::run()
{
    std::vector<epoll_event> events(128);
    while (true)
    {
        int nfds = epoll_wait(epoll_fd_, events.data(), events.size(), -1);
        if (nfds < 0)
        {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].data.fd == listen_fd_)
            {
                sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int conn_fd = accept(listen_fd_, (struct sockaddr *)&client_addr, &client_len);
                if (conn_fd < 0)
                {
                    perror("accept");
                    exit(EXIT_FAILURE);
                }
                addToEpoll(epoll_fd_, conn_fd);
            }
            else
            {
                handleMessage(events[i].data.fd);
            }
        }
    }

    close(epoll_fd_);
}

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

void discon(int fd, int epfd)
{
    int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    if (ret < 0)
    {
        perror("EPOLL_CTL_DEL error...\n");
    }
    close(fd);
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