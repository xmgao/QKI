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
    // api������IPSec������QKI�����ӣ�����1���ɹ���0��ʧ�ܣ�����QKI_IP_ADDRESS��QKI_LISTEN_PORT������conn_QKI_fd
    bool connectQKI(int &conn_QKI_fd, const std::string &QKI_IP_ADDRESS, int QKI_LISTEN_PORT);

    // api������IPSec����һ��IKESA�Ự���޷���ֵ�����뷢��IP��ַsrcip, ���շ�IP��ַdstip, ����SPIspiI, spiR, conn_QKI_fd�������ֽ��򣬴�IKE_SA
    void openIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR);

    // app������IPSec��ȡIKESA��һ��key,����conn_QKI_fd, spiI, spiR, request_id, request_len, ���ص�������ԿID��qkey_id ,��Կ����qkeybuffer������1���ɹ���0��ʧ�ܣ�
    bool getIKESAkey(const int conn_QKI_fd, const uint64_t spiI, const uint64_t spiR,
                     uint32_t request_id, uint16_t request_len, uint32_t &qkey_id, std::vector<uint8_t> &qkeybuffer);

    // api������IPSec�ر���QKI��һ��IKESA�Ự���޷���ֵ������srcip, dstip, spiI, spiR, conn_QKI_fd�������ֽ���
    void closeIKESAsession(const int conn_QKI_fd, uint32_t srcip, uint32_t dstip, const uint64_t spiI, const uint64_t spiR);

    // api������IPSec�ر���QKI�����ӣ��޷���ֵ������conn_QKI_fd
    bool closeQKI(int &conn_QKI_fd);

    void openIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                            const uint32_t spi, bool is_inbound, bool is_otpalg);

    bool getIPecSAkey(const int conn_QKI_fd, uint32_t spi,
                      uint32_t request_id, uint16_t request_len, uint32_t &qkey_id, std::vector<uint8_t> &qkeybuffer);

    void closeIPSecSAsession(const int conn_QKI_fd, const uint32_t IPPROACTIVE, const uint32_t IPPASSIVE,
                        const uint32_t spi, bool is_inbound, bool is_otpalg);
                        
} // namespace my_qki_qpi

#endif // QKI_API_HPP