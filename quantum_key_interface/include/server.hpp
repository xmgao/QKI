#ifndef SERVER_HPP
#define SERVER_HPP

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

const int PORT_KM = 50000;
const int LISTEN_PORT_IPSec = 50001;

class Server
{
public:
    Server(int port);
    ~Server();
    void run();
    int epoll_fd_;

private:
    void handleMessage(int fd);

    int createAndBindSocket(int port);
    int port_;
    int listen_fd_;
};

// 事件监听
void addToEpoll(int epoll_fd, int fd);

// 发起tcp连接
int connectToServer(const std::string &ipAddress, int port);

// 关闭tcp连接，事件删除
void discon(int fd, int epfd);

std::string uint32ToIpString(uint32_t ipNumeric);

uint32_t IpStringTouint32(const std::string &ipString);

#endif // SERVER_H