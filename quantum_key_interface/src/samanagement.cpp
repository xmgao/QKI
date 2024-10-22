#include "samanagement.hpp"
#include "packet/packets.hpp"
#include "server.hpp"
#include <thread>
#include <chrono>

// 声明全局变量，但不定义
extern SAManager globalSAManager;
const int KM_LISTEN_PORT = 50000;

SAManager::SAManager()
    : SA_number(0) {}

bool connect_KM(SAData &sadata)
{
    // 连接KM
    int conn_KM_fd = -1;
    const int max_retries = 10; // 设置最大重试次数
    int retries = 0;
    const std::string KM_IP_ADDRESS = "127.0.0.1";

    while (conn_KM_fd <= 0 && retries < max_retries)
    {
        conn_KM_fd = connectToServer(KM_IP_ADDRESS, KM_LISTEN_PORT);
        if (conn_KM_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2)); // 等待2秒
            retries++;
        }
    }
    // 检查连接状态并处理失败情况
    if (conn_KM_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        return false;
    }
    // 如果成功，继续处理连接
    std::cout << "Connected successfully!" << std::endl;
    sadata.KM_fd_ = conn_KM_fd;
    return true;
}

// SA向KM打开一个会话
bool opensession(SAData &sadata)
{
    // 打开会话
    OpenSessionPacket pkt1;
    uint32_t sourceip = sadata.sourceip_;
    uint32_t desip = sadata.desip_;
    uint32_t session_id = sadata.spi_;
    pkt1.constructopensessionpacket(sourceip, desip, session_id, !sadata.is_inbound_);
    send(sadata.KM_fd_, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
    return false;
}

// SA通过会话向KM索取密钥，另一种模式是自己管理密钥
bool addKey(SAData &sadata)
{
    int request_len = 512;
    // 构造请求密钥包
    KeyRequestPacket pkt2;
    pkt2.constructkeyrequestpacket(sadata.spi_, 1, request_len);
    if (send(sadata.KM_fd_, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
    {
        perror("send Error");
        close(sadata.KM_fd_);
        return 0;
    }

    // 处理密钥返回
    PacketBase pkt3;
    // 读取packet header
    ssize_t bytes_read = read(sadata.KM_fd_, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
    if (bytes_read <= 0)
    {
        perror("read Error");
        close(sadata.KM_fd_);
        return 0;
    }

    uint16_t value1, length;
    std::memcpy(&value1, pkt3.getBufferPtr(), sizeof(uint16_t));
    std::memcpy(&length, pkt3.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

    // 读取payload
    bytes_read = read(sadata.KM_fd_, pkt3.getBufferPtr() + BASE_HEADER_SIZE, length);
    if (bytes_read != length)
    {
        perror("Incomplete payload read");
        close(sadata.KM_fd_);
        return 0;
    }
    pkt3.setBufferSize(BASE_HEADER_SIZE + length);
    std::string getkeyvalue;
    if (value1 == static_cast<uint16_t>(PacketType::KEYRETURN))
    {
        // 带参构造KeyRequestPacket
        KeyRequestPacket pkt4(std::move(pkt3));
        getkeyvalue.resize(request_len);
        std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
    }
    else
    {
        perror("getkey Error");
        return false;
    }
}

// SA向KM关闭一个会话
void closesession(SAData &sadata)
{
    // 关闭会话
    OpenSessionPacket closepkt;
    closepkt.constructclosesessionpacket(sadata.sourceip_, sadata.desip_, sadata.spi_, !sadata.is_inbound_);
    send(sadata.KM_fd_, closepkt.getBufferPtr(), closepkt.getBufferSize(), 0);
    close(sadata.KM_fd_);
}

bool SAManager::registerSA(uint32_t sourceip, uint32_t desip, uint32_t spi, bool is_inbound)
{

    std::lock_guard<std::mutex> lock(mutex_);
    // 检查SA是否已存在
    auto it = SACache_.find(spi);
    if (it != SACache_.end())
    {
        std::cerr << "SA already exists" << std::endl;
        return false; // 会话已存在
    }
    // 创建新的KeyData对象并插入映射
    SAData newSAData;
    newSAData.sourceip_ = sourceip;
    newSAData.desip_ = desip;
    newSAData.spi_ = spi;
    newSAData.is_inbound_ = is_inbound;
    // 判断是否是主动端
    if (!is_inbound)
    {
        connect_KM(newSAData);  // 如果是主动端打开与KM的会话，被动端不需要提前打开会话，由主动端KM打开
        opensession(newSAData); // TODO：打开会话,协议转换
    }
    SACache_[spi] = newSAData;
    ++SA_number;
    return true;
}

std::string SAManager::getKey(uint32_t spi, uint32_t seq, uint16_t request_len)
{
    auto it = SACache_.find(spi);
    if (it != SACache_.end())
    {
        // 返回找到的密钥
        int useful_size = it->second.keybuffer.size() - it->second.index_;
        while (useful_size < request_len)
        {
            // TODO:补充密钥
            if (!addKey(it->second))
            {
                // 错误处理
                std::cerr << "addproactivekey failed." << std::endl;
                return "";
            }
            useful_size = it->second.keybuffer.size() - it->second.index_;
        }
        std::string returnkeyvalue(it->second.keybuffer.begin() + it->second.index_, it->second.keybuffer.begin() + it->second.index_ + request_len);
        it->second.index_ += request_len;
        return returnkeyvalue;
    }
    return ""; // 如果未找到，返回空字符串
}

bool SAManager::destorySA(uint32_t spi)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = SACache_.find(spi);
    if (it != SACache_.end())
    {
        closesession(it->second); // TODO:首先通知关闭与KM的会话

        SACache_.erase(it);
        --SA_number;
        std::cout << "destorySA success!spi:" << spi << std::endl;
        return true;
    }
    else
    {
        // 错误处理
        std::cerr << "destorySA failed!Unable to find session" << std::endl;
    }
    return false;
}
