#ifndef SAMANAGEMENT_HPP
#define SAMANAGEMENT_HPP

#include <iostream>
#include <string>
#include <mutex>
#include <iomanip>
#include <stdexcept>
#include <unordered_map>
#include <cstdint>
#include <vector>
#include <queue>
#include "qkdf/qkdf.hpp"

// �Զ���ṹ����ʾ 128 λ�� SPI
struct IKE_SPI
{
    uint64_t spi_i;
    uint64_t spi_r;

    bool operator==(const IKE_SPI &other) const
    {
        return spi_i == other.spi_i && spi_r == other.spi_r;
    }
};

// �Զ����ϣ����
struct IKE_SPI_Hash
{
    std::size_t operator()(const IKE_SPI &spi) const
    {
        // �򵥵Ĺ�ϣ���
        return std::hash<uint64_t>()(spi.spi_i) ^ std::hash<uint64_t>()(spi.spi_r);
    }
};

// ʾ���� SA ���ݽṹ
struct IKE_SAData
{
    uint64_t spiI_;
    uint64_t spiR_;
    uint32_t sourceip_;
    uint32_t desip_;
    // ����Ƿ���true
    bool is_initiator;
    // IKESA��Ӧ�ĻỰID
    uint32_t session_id_;
    int index_ = 0;
    int KM_fd_ = -1;
    int request_id = 0;
    std::vector<uint8_t> keybuffer; // ԭʼ��Կ����
};

struct IPSec_SAData
{
    uint32_t spi_;
    uint32_t sourceip_;
    uint32_t desip_;
    // ��ʶ����վSA���ǳ�վSA,true�������վSA
    bool is_inbound_;
    // IPSecSA��Ӧ�ĻỰID
    uint32_t session_id_;
    int index_ = 0;
    int KM_fd_ = -1;
    int request_id = 0;
    std::vector<uint8_t> keybuffer; // ԭʼ��Կ����
    QKDF qkdf_;
    std::vector<uint8_t> keyderive; // ��Կ��������
};

class SAManager
{
public:
    uint32_t mapIKESpiToSessionId(const IKE_SPI &spi)
    {
        // ʹ���Զ����ϣ��������32λ�ỰID
        IKE_SPI_Hash hasher;
        uint32_t sessionId = static_cast<uint32_t>(hasher(spi));

        // ����ͻ������
        while (sessionIDToIKESPI.find(sessionId) != sessionIDToIKESPI.end() || sessionIDToIPSecSPI.find(sessionId) != sessionIDToIPSecSPI.end())
        {
            sessionId++;
        }
        sessionIDToIKESPI[sessionId] = spi;
        // ����һ���޳�ͻ�ĻỰID
        return sessionId;
    }
    uint32_t mapIPSecSpiToSessionId(const uint32_t spi)
    {
        // ʹ��std::hash<uint32_t>����32λ�ỰID
        std::hash<uint32_t> hasher;
        uint32_t sessionId = hasher(spi);

        // ����ͻ������
        while (sessionIDToIKESPI.find(sessionId) != sessionIDToIKESPI.end() || sessionIDToIPSecSPI.find(sessionId) != sessionIDToIPSecSPI.end())
        {
            sessionId++;
        }
        sessionIDToIPSecSPI[sessionId] = spi;
        // ����һ���޳�ͻ�ĻỰID
        return sessionId;
    }
    // ���캯��
    SAManager();

    // ע��IPSecSA
    bool registerIPSecSA(uint32_t sourceip, uint32_t desip, uint32_t spi, bool is_inbound);

    // ��ȡIPSecSA��Կ��ͨ��request��ȡ
    std::string getIPSecKey(uint32_t spi, uint32_t seq, uint16_t request_len);

    // ɾ��IPSecSA�Ự��ͨ��session_idɾ��
    bool destoryIPSecSA(uint32_t spi);

    // ע��IKESA
    bool registerIKESA(uint32_t sourceip, uint32_t desip, uint64_t spiI, uint64_t spiR);

    // ��ȡIKESA��Կ��ͨ��request��ȡ
    std::string getIKESAKey(uint64_t spiI, uint64_t spiR, uint32_t seq, uint16_t request_len);

    // ɾ��IKESA�Ự��ͨ��spiɾ��
    bool destoryIKESA(uint64_t spiI, uint64_t spiR);

private:
    std::mutex mutex_;
    // ����IPSec spi��IPSecSAData��ӳ��
    std::unordered_map<uint32_t, IPSec_SAData> IPSec_SACache_;
    // ����IKE spi��IKESAData��ӳ��
    std::unordered_map<IKE_SPI, IKE_SAData, IKE_SPI_Hash> IKE_SACache_;
    // ����ȫ��IPSec SA����
    int IPSecSA_number;
    // ����Ựid��IKE_SPI��ӳ��
    std::unordered_map<uint32_t, IKE_SPI> sessionIDToIKESPI;
    // ����Ựid��IPSec_SPI��ӳ��
    std::unordered_map<uint32_t, uint32_t> sessionIDToIPSecSPI;
};

#endif // SAMANAGEMENT_HPP