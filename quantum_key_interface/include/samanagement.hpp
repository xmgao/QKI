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

struct SAData
{
    std::vector<uint8_t> keybuffer; // 原始密钥缓存
    std::vector<uint8_t> keyderive; // 密钥派生缓存
    uint32_t spi_;
    uint32_t sourceip_;
    uint32_t desip_;
    int index_ = 0;
    int KM_fd_ = -1;
    // 标识是入站SA还是出站SA,true如果是入站SA
    bool is_inbound_;
    // 新增成员：用于存储使用过的seq的队列
    std::queue<int> usedSeq;
};

class SAManager
{
public:
    // 构造函数
    SAManager();

    // 注册SA
    bool registerSA(uint32_t sourceip, uint32_t desip, uint32_t spi, bool is_inbound);

    // 获取密钥，通过request读取
    std::string getKey(uint32_t spi, uint32_t seq, uint16_t request_len);

    // 删除会话，通过session_id删除
    bool destorySA(uint32_t spi);

private:
    std::mutex mutex_;
    // 定义spi到SAData的映射
    std::unordered_map<uint32_t, SAData> SACache_;
    // 定义全局sa数量
    int SA_number;
};

#endif // SAMANAGEMENT_HPP