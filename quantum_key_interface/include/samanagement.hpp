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

// 自定义结构来表示 128 位的 SPI
struct IKE_SPI
{
    uint64_t spi_i;
    uint64_t spi_r;

    bool operator==(const IKE_SPI &other) const
    {
        return spi_i == other.spi_i && spi_r == other.spi_r;
    }
};

// 自定义哈希函数
struct IKE_SPI_Hash
{
    std::size_t operator()(const IKE_SPI &spi) const
    {
        // 简单的哈希组合
        return std::hash<uint64_t>()(spi.spi_i) ^ std::hash<uint64_t>()(spi.spi_r);
    }
};

// 示例的 SA 数据结构
struct IKE_SAData
{
    uint64_t spiI_;
    uint64_t spiR_;
    uint32_t sourceip_;
    uint32_t desip_;
    // 如果是发起方true
    bool is_initiator;
    // IKESA对应的会话ID
    uint32_t session_id_;
    int index_ = 0;
    int KM_fd_ = -1;
    int request_id = 0;
    std::vector<uint8_t> keybuffer; // 原始密钥缓存
};

struct IPSec_SAData
{
    uint32_t spi_;
    uint32_t sourceip_;
    uint32_t desip_;
    // 标识是入站SA还是出站SA,true如果是入站SA
    bool is_inbound_;
    // IPSecSA对应的会话ID
    uint32_t session_id_;
    int index_ = 0;
    int KM_fd_ = -1;
    int request_id = 0;
    std::vector<uint8_t> keybuffer; // 原始密钥缓存
    QKDF qkdf_;
    std::vector<uint8_t> keyderive; // 密钥派生缓存
};

class SAManager
{
public:
    uint32_t mapIKESpiToSessionId(const IKE_SPI &spi)
    {
        // 使用自定义哈希函数生成32位会话ID
        IKE_SPI_Hash hasher;
        uint32_t sessionId = static_cast<uint32_t>(hasher(spi));

        // 检测冲突并处理
        while (sessionIDToIKESPI.find(sessionId) != sessionIDToIKESPI.end() || sessionIDToIPSecSPI.find(sessionId) != sessionIDToIPSecSPI.end())
        {
            sessionId++;
        }
        sessionIDToIKESPI[sessionId] = spi;
        // 返回一个无冲突的会话ID
        return sessionId;
    }
    uint32_t mapIPSecSpiToSessionId(const uint32_t spi)
    {
        // 使用std::hash<uint32_t>生成32位会话ID
        std::hash<uint32_t> hasher;
        uint32_t sessionId = hasher(spi);

        // 检测冲突并处理
        while (sessionIDToIKESPI.find(sessionId) != sessionIDToIKESPI.end() || sessionIDToIPSecSPI.find(sessionId) != sessionIDToIPSecSPI.end())
        {
            sessionId++;
        }
        sessionIDToIPSecSPI[sessionId] = spi;
        // 返回一个无冲突的会话ID
        return sessionId;
    }
    // 构造函数
    SAManager();

    // 注册IPSecSA
    bool registerIPSecSA(uint32_t sourceip, uint32_t desip, uint32_t spi, bool is_inbound);

    // 获取IPSecSA密钥，通过request读取
    std::string getIPSecKey(uint32_t spi, uint32_t seq, uint16_t request_len);

    // 删除IPSecSA会话，通过session_id删除
    bool destoryIPSecSA(uint32_t spi);

    // 注册IKESA
    bool registerIKESA(uint32_t sourceip, uint32_t desip, uint64_t spiI, uint64_t spiR);

    // 获取IKESA密钥，通过request读取
    std::string getIKESAKey(uint64_t spiI, uint64_t spiR, uint32_t seq, uint16_t request_len);

    // 删除IKESA会话，通过spi删除
    bool destoryIKESA(uint64_t spiI, uint64_t spiR);

private:
    std::mutex mutex_;
    // 定义IPSec spi到IPSecSAData的映射
    std::unordered_map<uint32_t, IPSec_SAData> IPSec_SACache_;
    // 定义IKE spi到IKESAData的映射
    std::unordered_map<IKE_SPI, IKE_SAData, IKE_SPI_Hash> IKE_SACache_;
    // 定义全局IPSec SA数量
    int IPSecSA_number;
    // 定义会话id到IKE_SPI的映射
    std::unordered_map<uint32_t, IKE_SPI> sessionIDToIKESPI;
    // 定义会话id到IPSec_SPI的映射
    std::unordered_map<uint32_t, uint32_t> sessionIDToIPSecSPI;
};

#endif // SAMANAGEMENT_HPP