#include "debuglevel.hpp"
#include "samanagement.hpp"
#include "packet/packets.hpp"
#include "server.hpp"
#include <thread>
#include <chrono>

// 声明全局变量，但不定义
extern SAManager globalSAManager;
extern uint32_t LOCAL_QKI_IPADDRESS;
extern int KM_LISTEN_PORT;

SAManager::SAManager()
    : IPSecSA_number(0) {}

bool connect_KM(IPSec_SAData &sadata)
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

bool connect_KM(IKE_SAData &sadata)
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

bool reciveconfirmmessage(int conn_KM_fd)
{
    // 处理返回结果
    ConfirmMessagePacket response_pkt;

    // 读取 packet header
    ssize_t bytes_read = read(conn_KM_fd, response_pkt.getBufferPtr(), BASE_HEADER_SIZE);
    if (bytes_read <= 0)
    {
        std::cerr << "Failed to read response header or connection closed." << std::endl;
        close(conn_KM_fd);
        return false;
    }

    uint16_t value1, length;
    std::memcpy(&value1, response_pkt.getBufferPtr(), sizeof(uint16_t));
    std::memcpy(&length, response_pkt.getBufferPtr() + sizeof(uint16_t), sizeof(uint16_t));

    // 读取 payload
    bytes_read = read(conn_KM_fd, response_pkt.getBufferPtr() + BASE_HEADER_SIZE, length);
    if (bytes_read != length)
    {
        std::cerr << "Incomplete payload read. Expected: " << std::to_string(length) << ", got: " << std::to_string(bytes_read) << std::endl;
        close(conn_KM_fd);
        return false;
    }

    response_pkt.setBufferSize(BASE_HEADER_SIZE + length);
    if (value1 == static_cast<uint16_t>(PacketType::CONFIRMMESSAGE))
    {
        if (*response_pkt.geterrortypePtr() == static_cast<uint32_t>(ErrorCode::SUCCESS))
        {
            return true;
        }
        else
        {
            std::cerr << "Cannot open passive session, error code: " << std::to_string(*response_pkt.geterrortypePtr()) << std::endl;
        }
    }
    else
    {
        std::cerr << "Received unexpected message type: " << std::to_string(value1) << std::endl;
    }
    close(conn_KM_fd);
    return false;
}

// IPSecSA向KM打开一个会话,只需要主动端打开
bool opensession(IPSec_SAData &sadata)
{
    // 打开会话
    OpenSessionPacket pkt1;
    // 将LOCAL_QKI_IPADDRESS和REMOTE_QKI_IPADDRESS替换成IPsec传递的IP，IPSEc SA和IKE SA一致
    pkt1.constructopensessionpacket(sadata.sourceip_, sadata.desip_, sadata.session_id_, sadata.is_inbound_);
    send(sadata.KM_fd_, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
    if (!reciveconfirmmessage(sadata.KM_fd_))
    {
        std::cerr << "Failed to connect receive confirm message" << std::endl;
        return false;
    }
    return true;
}

// IKESA向KM打开一个会话,只需要主动端打开
bool opensession(IKE_SAData &sadata)
{
    // 打开会话
    OpenSessionPacket pkt1;
    pkt1.constructopensessionpacket(sadata.sourceip_, sadata.desip_, sadata.session_id_, !sadata.is_initiator);
    send(sadata.KM_fd_, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
    if (!reciveconfirmmessage(sadata.KM_fd_))
    {
        std::cerr << "Failed to connect receive confirm message" << std::endl;
        return false;
    }
    return true;
}

// SA通过会话向KM索取密钥，另一种模式是自己管理密钥
bool addKey(IPSec_SAData &sadata)
{
    const int max_retries = 5; // 设置最大重试次数
    int retries = 0;
    int request_len = 0;
    if (sadata.use_qkdf_)
    {
        request_len = sadata.qkdf_.BlockSize; // 每次请求一个mdk
    }
    else
    {
        request_len = 512;
    }
    sadata.request_id += 1; // 每次请求的id递增
    // 重试5次
    while (retries < max_retries)
    {
        // 构造请求密钥包
        KeyRequestPacket pkt2;
        pkt2.constructkeyrequestpacket(sadata.session_id_, sadata.request_id, request_len);
        if (send(sadata.KM_fd_, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(sadata.KM_fd_);
            return false;
        }
        // 处理密钥返回
        PacketBase pkt3;
        // 读取packet header
        ssize_t bytes_read = read(sadata.KM_fd_, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
        if (bytes_read <= 0)
        {
            perror("read Error");
            close(sadata.KM_fd_);
            return false;
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
            return false;
        }
        pkt3.setBufferSize(BASE_HEADER_SIZE + length);
        std::string getkeyvalue;
        if (value1 == static_cast<uint16_t>(PacketType::KEYRETURN))
        {
            // 带参构造KeyRequestPacket,成功返回mdk字节密钥，插入到buffer末尾
            KeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
            if (sadata.use_qkdf_)
            {
                sadata.keybuffer.insert(sadata.keybuffer.end(), getkeyvalue.begin(), getkeyvalue.end()); // 存入原始密钥
                // 获取派生材料
                std::vector<uint8_t> input_key_buf(getkeyvalue.begin(), getkeyvalue.begin() + request_len);
                // 获取开始时间点
                auto start = std::chrono::high_resolution_clock::now();
                byte output = sadata.qkdf_.SingleRound(input_key_buf); // 进行派生
                if (DEBUG_LEVEL <= 0)
                {
                    // 获取结束时间点
                    auto end = std::chrono::high_resolution_clock::now();
                    // 计算时间差并转换为微秒
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
                    // 输出时间
                    std::cout << "SingleRoundderive took " << duration << " microseconds." << std::endl;
                }
                sadata.keyderive.insert(sadata.keyderive.end(), output.begin(), output.end()); // 插入派生密钥到末尾
            }
            else
            {
                sadata.keybuffer.insert(sadata.keybuffer.end(), getkeyvalue.begin(), getkeyvalue.end());
            }

            return true;
        }

        if (sadata.is_inbound_ && retries < max_retries)
        {
            // 如果是被动端返回密钥失败，可以进行重新尝试
            usleep(2000);
            retries++;
            std::cerr << "getIPSecSAkey Error, retrying..." << std::endl;
            continue;
        }
        else
        {
            break;
        }
    }
    // 返回密钥失败，返回错误消息
    std::cerr << "getIPSecSAkey Error" << std::endl;
    return false;
}

// SA通过会话向KM索取OTP密钥
bool addOTPKey(IPSec_SAData &sadata)
{
    const int max_retries = 5; // 设置最大重试次数
    int retries = 0;
    int request_len = sadata.qkdf_.BlockSize; // 每次请求一个mdk

    sadata.request_id += 1; // 每次请求的id递增
    // 重试5次
    while (retries < max_retries)
    {
        // 构造请求密钥包
        KeyRequestPacket pkt2;
        pkt2.constructkeyrequestpacket(sadata.session_id_, sadata.request_id, request_len);
        if (send(sadata.KM_fd_, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(sadata.KM_fd_);
            return false;
        }
        // 处理密钥返回
        PacketBase pkt3;
        // 读取packet header
        ssize_t bytes_read = read(sadata.KM_fd_, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
        if (bytes_read <= 0)
        {
            perror("read Error");
            close(sadata.KM_fd_);
            return false;
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
            return false;
        }
        pkt3.setBufferSize(BASE_HEADER_SIZE + length);
        std::string getkeyvalue;
        if (value1 == static_cast<uint16_t>(PacketType::KEYRETURN))
        {
            // 带参构造KeyRequestPacket,成功返回mdk字节密钥，插入到buffer末尾
            KeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
            // 获取派生材料
            std::vector<uint8_t> input_key_buf(getkeyvalue.begin(), getkeyvalue.begin() + request_len);
            byte output = sadata.qkdf_.SingleRound(input_key_buf, OTP_KEY_UNIT * NUM_BLOCK); // 进行派生
            for (uint32_t i = 0; i < NUM_BLOCK; ++i)
            {
                std::array<uint8_t, OTP_KEY_UNIT> block;
                // 将每个块的数据复制到数组中
                std::copy(output.begin() + i * OTP_KEY_UNIT, output.begin() + (i + 1) * OTP_KEY_UNIT, block.begin());
                // 将块插入到unordered_map中
                sadata.otpdata_.otpkey_map[sadata.otpdata_.seq_++] = block;
            }
            return true;
        }
        if (sadata.is_inbound_ && retries < max_retries)
        {
            // 如果是被动端返回密钥失败，可以进行重新尝试
            usleep(2000);
            retries++;
            std::cerr << "getIPSecSAkey Error, retrying..." << std::endl;
            continue;
        }
        else
        {
            break;
        }
    }
    // 返回密钥失败，返回错误消息
    std::cerr << "getIPSecSAOTPkey Error" << std::endl;
    return false;
}

bool addKey(IKE_SAData &sadata)
{
    int request_len = 512;

    const int max_retries = 5; // 设置最大重试次数
    int retries = 0;
    sadata.request_id += 1; // 每次请求的id递增
    // 重试5次
    while (retries < max_retries)
    {
        // 构造请求密钥包
        KeyRequestPacket pkt2;
        pkt2.constructkeyrequestpacket(sadata.session_id_, sadata.request_id, request_len);
        if (send(sadata.KM_fd_, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
        {
            perror("send Error");
            close(sadata.KM_fd_);
            return false;
        }
        // 处理密钥返回
        PacketBase pkt3;
        // 读取packet header
        ssize_t bytes_read = read(sadata.KM_fd_, pkt3.getBufferPtr(), BASE_HEADER_SIZE);
        if (bytes_read <= 0)
        {
            perror("read Error");
            close(sadata.KM_fd_);
            return false;
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
            return false;
        }
        pkt3.setBufferSize(BASE_HEADER_SIZE + length);
        std::string getkeyvalue;
        if (value1 == static_cast<uint16_t>(PacketType::KEYRETURN))
        {
            // 带参构造KeyRequestPacket,成功返回512字节密钥，插入到buffer末尾
            KeyRequestPacket pkt4(std::move(pkt3));
            getkeyvalue.resize(request_len);
            std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
            sadata.keybuffer.insert(sadata.keybuffer.end(), getkeyvalue.begin(), getkeyvalue.end());
            return true;
        }
        if (!sadata.is_initiator && retries < max_retries)
        {
            // 如果是被动端返回密钥失败，可以进行重新尝试
            usleep(2000);
            retries++;
            std::cerr << "getIKESAkey Error, retrying..." << std::endl;
            continue;
        }
        else
        {
            break;
        }
    }
    // 返回密钥失败，返回错误消息
    std::cerr << "getIKESAkey Error" << std::endl;
    return false;
}

// SA向KM关闭一个会话
void closesession(IPSec_SAData &sadata)
{
    // 关闭会话
    OpenSessionPacket closepkt;
    closepkt.constructclosesessionpacket(sadata.sourceip_, sadata.desip_, sadata.session_id_, sadata.is_inbound_);
    send(sadata.KM_fd_, closepkt.getBufferPtr(), closepkt.getBufferSize(), 0);
    close(sadata.KM_fd_);
}

void closesession(IKE_SAData &sadata)
{
    // 关闭会话
    OpenSessionPacket closepkt;
    closepkt.constructclosesessionpacket(sadata.sourceip_, sadata.desip_, sadata.session_id_, !sadata.is_initiator);
    send(sadata.KM_fd_, closepkt.getBufferPtr(), closepkt.getBufferSize(), 0);
    close(sadata.KM_fd_);
}

bool SAManager::registerIPSecSA(uint32_t sourceip, uint32_t desip, uint32_t spi, bool is_inbound, bool is_otpalg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    // 检查SA是否已存在
    auto it = IPSec_SACache_.find(spi);
    if (it != IPSec_SACache_.end())
    {
        std::cerr << "SA already exists" << std::endl;
        return false; // 会话已存在
    }
    // 创建新的KeyData对象并插入映射
    IPSec_SAData newSAData;
    newSAData.sourceip_ = sourceip;
    newSAData.desip_ = desip;
    newSAData.spi_ = spi;
    newSAData.is_inbound_ = is_inbound;
    newSAData.is_otpalg_ = is_otpalg;
    if (is_otpalg)
    {
        newSAData.use_qkdf_ = true;
        newSAData.qkdf_.SetName(std::to_string(spi));
        newSAData.qkdf_.Initialized();
    }
    else
    {
        newSAData.use_qkdf_ = false; // 默认不开启
    }

    newSAData.session_id_ = globalSAManager.mapIPSecSpiToSessionId(spi); // 调用成员函数
    if (!connect_KM(newSAData))
    {
        std::cerr << "connect km error" << std::endl;
        return false;
    }
    // 判断是否是主动端
    if (!is_inbound)
    {
        // 如果是主动端打开与KM的会话，被动端不需要提前打开会话，由主动端KM打开
        if (!opensession(newSAData))
        {
            std::cerr << "open session error" << std::endl;
            return false;
        }
    }
    IPSec_SACache_[spi] = newSAData;
    ++IPSecSA_number;
    return true;
}

std::string SAManager::getIPSecKey(uint32_t spi, uint32_t seq, uint16_t request_len)
{
    auto it = IPSec_SACache_.find(spi);
    if (it != IPSec_SACache_.end())
    {
        if (it->second.is_otpalg_)
        {
            // 查找密钥缓存map
            auto &otpkey_map = it->second.otpdata_.otpkey_map;
            auto it_key = otpkey_map.find(seq);

            // 补充密钥，直到找到为止
            while (it_key == otpkey_map.end())
            {
                if (!addOTPKey(it->second))
                {
                    std::cerr << "Failed to add IPsecSA OTP key." << std::endl;
                    return ""; // 直接返回空字符串，让上层重试
                }
                it_key = otpkey_map.find(seq);
            }

            // 检查请求长度是否超出允许的最大块大小
            if (request_len > OTP_KEY_UNIT)
            {
                std::cerr << "Request length exceeds the maximum block size." << std::endl;
                return ""; // 返回空字符串，表示错误
            }

            // 将找到的密钥初始化为 std::string，并返回
            std::string return_key_value(it_key->second.begin(), it_key->second.begin() + request_len);

            // 使用后从map中删除密钥
            otpkey_map.erase(it_key);

            return return_key_value;
        }
        else
        {
            std::vector<uint8_t> &bufferptr = (it->second.use_qkdf_) ? it->second.keyderive : it->second.keybuffer;
            int useful_size = bufferptr.size();

            while (useful_size < request_len)
            {
                // 补充密钥
                if (!addKey(it->second))
                {
                    // 如果是加密方，补充密钥失败说明KM密钥不足，不尝试重新获取密钥
                    // 如果是解密方补充密钥失败，有可能是密钥不足，也有可能是密钥未同步过去，需要循环多次尝试重新请求
                    // 错误处理
                    std::cerr << "add ipsecsa key failed." << std::endl;
                    return "";
                }
                useful_size = bufferptr.size();
            }

            std::string returnkeyvalue(bufferptr.begin(), bufferptr.begin() + request_len);
            bufferptr.erase(bufferptr.begin(), bufferptr.begin() + request_len); // 用后删除
            return returnkeyvalue;
        }
    }
    return ""; // 如果未找到spi，返回空字符串
}

bool SAManager::destoryIPSecSA(uint32_t spi)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = IPSec_SACache_.find(spi);
    if (it != IPSec_SACache_.end())
    {
        closesession(it->second); // 首先通知关闭与KM的会话
        IPSec_SACache_.erase(it);
        --IPSecSA_number;
        std::cout << "destoryIPSecSA success!spi:" << spi << std::endl;
        return true;
    }
    else
    {
        // 错误处理
        std::cerr << "destoryIPSecSA failed!Unable to find ipsec sa:" << spi << std::endl;
    }
    return false;
}

bool SAManager::registerIKESA(uint32_t sourceip, uint32_t desip, uint64_t spiI, uint64_t spiR)
{

    IKE_SPI Spitemple = {spiI, spiR};

    // 检查IKESA是否已存在
    if (IKE_SACache_.find(Spitemple) != IKE_SACache_.end())
    {
        std::cout << "Found IKE SA!" << std::endl;
        return false;
    }
    // 创建新的IKE_SAData对象并插入映射
    IKE_SAData newSAData;
    newSAData.sourceip_ = sourceip;
    newSAData.desip_ = desip;
    newSAData.spiI_ = spiI;
    newSAData.spiR_ = spiR;
    // 如果发起方地址就是本地QKI地址，则本身为发起方，发起方作为主动端
    newSAData.is_initiator = (sourceip == LOCAL_QKI_IPADDRESS ? true : false);
    newSAData.session_id_ = globalSAManager.mapIKESpiToSessionId(Spitemple); // 调用成员函数
    if (!connect_KM(newSAData))
    {
        std::cerr << "connect km error" << std::endl;
        return false;
    }
    // 判断是否是主动端
    if (newSAData.is_initiator)
    {
        // 如果是主动端打开与KM的会话，被动端不需要提前打开会话，由主动端KM打开
        if (!opensession(newSAData))
        {
            std::cerr << "open session error" << std::endl;
            return false;
        }
    }
    IKE_SACache_[Spitemple] = newSAData;
    return true;
}

std::string SAManager::getIKESAKey(uint64_t spiI, uint64_t spiR, uint32_t seq, uint16_t request_len)
{
    IKE_SPI Spitemple = {spiI, spiR};
    auto it = IKE_SACache_.find(Spitemple);
    if (it != IKE_SACache_.end())
    {
        // 返回找到的密钥
        int useful_size = it->second.keybuffer.size() - it->second.index_;
        while (useful_size < request_len)
        {
            // 补充密钥
            if (!addKey(it->second))
            {
                // 错误处理
                std::cerr << "add ikesa key failed." << std::endl;
                return "";
            }
            useful_size = it->second.keybuffer.size() - it->second.index_;
        }
        std::string returnkeyvalue(it->second.keybuffer.begin() + it->second.index_, it->second.keybuffer.begin() + it->second.index_ + request_len);
        it->second.index_ += request_len;
        return returnkeyvalue;
    }
    return ""; // 如果未找到spi，返回空字符串
}

bool SAManager::destoryIKESA(uint64_t spiI, uint64_t spiR)
{
    IKE_SPI Spitemple = {spiI, spiR};
    auto it = IKE_SACache_.find(Spitemple);
    if (it != IKE_SACache_.end())
    {
        closesession(it->second); // 首先通知关闭与KM的会话
        IKE_SACache_.erase(it);
        std::cout << "destoryIKESA success!spi:" << spiI << " and " << spiR << std::endl;
        return true;
    }
    else
    {
        // 错误处理
        std::cerr << "destoryIKESA failed!Unable to find spi:" << spiI << " and " << spiR << std::endl;
    }
    return false;
}
