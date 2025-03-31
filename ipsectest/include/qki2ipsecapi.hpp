#ifndef QKI_API_HPP
#define QKI_API_HPP

#include "packets.hpp"

#include <netinet/in.h> // for sockaddr_in
#include <iostream>     // for std::cout
#include <string>       // for std::string
#include <cstring>      // for std::memset
#include <unistd.h>     // for close()
#include <arpa/inet.h>  // for inet_pton
#include <sys/socket.h> // for socket
#include <unistd.h>     // for close()
#include <vector>       // for std::vector

namespace my_qki_qpi
{
    // api函数，IPSec建立与QKI的连接，返回1，成功；0，失败；传入QKI_IP_ADDRESS和QKI_LISTEN_PORT，返回conn_QKI_fd
    bool connectQKI(int &conn_QKI_fd, const std::string &QKI_IP_ADDRESS, int QKI_LISTEN_PORT);

    // api函数，IPSec创建一个IKESA会话，无返回值，传入发起方IP地址srcip, 接收方IP地址dstip, 发起方SPIspiI, spiR, conn_QKI_fd，网络字节序，打开IKE_SA
    void openIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR);

    // app函数，IPSec获取IKESA的一个key,传入conn_QKI_fd, spiI, spiR, request_id, request_len, 返回的量子密钥ID，qkey_id ,密钥缓存qkeybuffer，返回1，成功；0，失败；
    bool getIKESAkey(const int conn_QKI_fd, const uint64_t spiI, const uint64_t spiR,
                     uint32_t request_id, uint16_t request_len, uint32_t &qkey_id, std::vector<uint8_t> &qkeybuffer);

    // api函数，IPSec关闭与QKI的一个IKESA会话，无返回值，传入srcip, dstip, spiI, spiR, conn_QKI_fd，网络字节序
    void closeIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR);

    // api函数，IPSec关闭与QKI的连接，无返回值，传入conn_QKI_fd
    bool closeQKI(int &conn_QKI_fd);

    void openIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                            const uint32_t spi, bool is_inbound, bool is_otpalg);

    bool getIPecSAkey(const int conn_QKI_fd, uint32_t spi,
                      uint32_t request_id, uint16_t request_len, uint32_t &qkey_id, std::vector<uint8_t> &qkeybuffer);

    void closeIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                        const uint32_t spi, bool is_inbound, bool is_otpalg);
                        
} // namespace my_qki_qpi

#endif // QKI_API_HPP