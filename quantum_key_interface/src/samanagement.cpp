#include "samanagement.hpp"
#include "packet/packets.hpp"
#include "server.hpp"
#include <thread>
#include <chrono>

// ����ȫ�ֱ�������������
extern SAManager globalSAManager;
extern uint32_t LOCAL_QKI_IPADDRESS;
const int KM_LISTEN_PORT = 50000;

SAManager::SAManager()
    : IPSecSA_number(0) {}

bool connect_KM(IPSec_SAData &sadata)
{
    // ����KM
    int conn_KM_fd = -1;
    const int max_retries = 10; // ����������Դ���
    int retries = 0;
    const std::string KM_IP_ADDRESS = "127.0.0.1";

    while (conn_KM_fd <= 0 && retries < max_retries)
    {
        conn_KM_fd = connectToServer(KM_IP_ADDRESS, KM_LISTEN_PORT);
        if (conn_KM_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2)); // �ȴ�2��
            retries++;
        }
    }
    // �������״̬������ʧ�����
    if (conn_KM_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        return false;
    }
    // ����ɹ���������������
    std::cout << "Connected successfully!" << std::endl;
    sadata.KM_fd_ = conn_KM_fd;
    return true;
}

bool connect_KM(IKE_SAData &sadata)
{
    // ����KM
    int conn_KM_fd = -1;
    const int max_retries = 10; // ����������Դ���
    int retries = 0;
    const std::string KM_IP_ADDRESS = "127.0.0.1";

    while (conn_KM_fd <= 0 && retries < max_retries)
    {
        conn_KM_fd = connectToServer(KM_IP_ADDRESS, KM_LISTEN_PORT);
        if (conn_KM_fd <= 0)
        {
            std::cerr << "Failed to connect, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2)); // �ȴ�2��
            retries++;
        }
    }
    // �������״̬������ʧ�����
    if (conn_KM_fd <= 0)
    {
        std::cerr << "Failed to connect after " << max_retries << " retries." << std::endl;
        return false;
    }
    // ����ɹ���������������
    std::cout << "Connected successfully!" << std::endl;
    sadata.KM_fd_ = conn_KM_fd;
    return true;
}

bool reciveconfirmmessage(int conn_KM_fd)
{
    // �����ؽ��
    ConfirmMessagePacket response_pkt;

    // ��ȡ packet header
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

    // ��ȡ payload
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

// IPSecSA��KM��һ���Ự,ֻ��Ҫ�����˴�
bool opensession(IPSec_SAData &sadata)
{
    // �򿪻Ự
    OpenSessionPacket pkt1;
    pkt1.constructopensessionpacket(sadata.sourceip_, sadata.desip_, sadata.spi_, sadata.is_inbound_);
    send(sadata.KM_fd_, pkt1.getBufferPtr(), pkt1.getBufferSize(), 0);
    if (!reciveconfirmmessage(sadata.KM_fd_))
    {
        std::cerr << "Failed to connect receive confirm message" << std::endl;
        return false;
    }
    return true;
}

// IKESA��KM��һ���Ự,ֻ��Ҫ�����˴�
bool opensession(IKE_SAData &sadata)
{
    // �򿪻Ự
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

// SAͨ���Ự��KM��ȡ��Կ����һ��ģʽ���Լ�������Կ
bool addKey(IPSec_SAData &sadata)
{
    int request_len = 512;
    // ����������Կ��
    KeyRequestPacket pkt2;
    pkt2.constructkeyrequestpacket(sadata.spi_, sadata.request_id, request_len);
    if (send(sadata.KM_fd_, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
    {
        perror("send Error");
        close(sadata.KM_fd_);
        return false;
    }
    sadata.request_id += 1;
    // ������Կ����
    PacketBase pkt3;
    // ��ȡpacket header
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

    // ��ȡpayload
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
        // ���ι���KeyRequestPacket,�ɹ�����512�ֽ���Կ�����뵽bufferĩβ
        KeyRequestPacket pkt4(std::move(pkt3));
        getkeyvalue.resize(request_len);
        std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
        sadata.keybuffer.insert(sadata.keybuffer.end(), getkeyvalue.begin(), getkeyvalue.end());
        return true;
    }
    else
    {
        // ������Կʧ�ܣ����ش�����Ϣ
        perror("getkey Error");
        return false;
    }
}

bool addKey(IKE_SAData &sadata)
{
    int request_len = 512;
    // ����������Կ��
    KeyRequestPacket pkt2;
    pkt2.constructkeyrequestpacket(sadata.session_id_, sadata.request_id, request_len);
    if (send(sadata.KM_fd_, pkt2.getBufferPtr(), pkt2.getBufferSize(), 0) == -1)
    {
        perror("send Error");
        close(sadata.KM_fd_);
        return false;
    }
    sadata.request_id += 1;
    // ������Կ����
    PacketBase pkt3;
    // ��ȡpacket header
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

    // ��ȡpayload
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
        // ���ι���KeyRequestPacket,�ɹ�����512�ֽ���Կ�����뵽bufferĩβ
        KeyRequestPacket pkt4(std::move(pkt3));
        getkeyvalue.resize(request_len);
        std::memcpy(&getkeyvalue[0], pkt4.getKeyBufferPtr(), request_len);
        sadata.keybuffer.insert(sadata.keybuffer.end(), getkeyvalue.begin(), getkeyvalue.end());
        return true;
    }
    else
    {
        // ������Կʧ�ܣ����ش�����Ϣ
        perror("getkey Error");
        return false;
    }
}

// SA��KM�ر�һ���Ự
void closesession(IPSec_SAData &sadata)
{
    // �رջỰ
    OpenSessionPacket closepkt;
    closepkt.constructclosesessionpacket(sadata.sourceip_, sadata.desip_, sadata.spi_, sadata.is_inbound_);
    send(sadata.KM_fd_, closepkt.getBufferPtr(), closepkt.getBufferSize(), 0);
    close(sadata.KM_fd_);
}

void closesession(IKE_SAData &sadata)
{
    // �رջỰ
    OpenSessionPacket closepkt;
    closepkt.constructclosesessionpacket(sadata.sourceip_, sadata.desip_, sadata.session_id_, !sadata.is_initiator);
    send(sadata.KM_fd_, closepkt.getBufferPtr(), closepkt.getBufferSize(), 0);
    close(sadata.KM_fd_);
}

bool SAManager::registerIPSecSA(uint32_t sourceip, uint32_t desip, uint32_t spi, bool is_inbound)
{
    std::lock_guard<std::mutex> lock(mutex_);
    // ���SA�Ƿ��Ѵ���
    auto it = IPSecSACache_.find(spi);
    if (it != IPSecSACache_.end())
    {
        std::cerr << "SA already exists" << std::endl;
        return false; // �Ự�Ѵ���
    }
    // �����µ�KeyData���󲢲���ӳ��
    IPSec_SAData newSAData;
    newSAData.sourceip_ = sourceip;
    newSAData.desip_ = desip;
    newSAData.spi_ = spi;
    newSAData.is_inbound_ = is_inbound;
    if (!connect_KM(newSAData))
    {
        std::cerr << "connect km error" << std::endl;
        return false;
    }
    // �ж��Ƿ���������
    if (!is_inbound)
    {
        // ����������˴���KM�ĻỰ�������˲���Ҫ��ǰ�򿪻Ự����������KM��
        if (!opensession(newSAData))
        {
            std::cerr << "open session error" << std::endl;
            return false;
        }
    }
    IPSecSACache_[spi] = newSAData;
    ++IPSecSA_number;
    return true;
}

std::string SAManager::getIPSecKey(uint32_t spi, uint32_t seq, uint16_t request_len)
{
    auto it = IPSecSACache_.find(spi);
    if (it != IPSecSACache_.end())
    {
        // �����ҵ�����Կ
        int useful_size = it->second.keybuffer.size() - it->second.index_;
        while (useful_size < request_len)
        {
            // ������Կ
            if (!addKey(it->second))
            {
                // ������
                std::cerr << "add ipsecsa key failed." << std::endl;
                return "";
            }
            useful_size = it->second.keybuffer.size() - it->second.index_;
        }
        std::string returnkeyvalue(it->second.keybuffer.begin() + it->second.index_, it->second.keybuffer.begin() + it->second.index_ + request_len);
        it->second.index_ += request_len;
        return returnkeyvalue;
    }
    return ""; // ���δ�ҵ�spi�����ؿ��ַ���
}

bool SAManager::destoryIPSecSA(uint32_t spi)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = IPSecSACache_.find(spi);
    if (it != IPSecSACache_.end())
    {
        closesession(it->second); // TODO:����֪ͨ�ر���KM�ĻỰ
        IPSecSACache_.erase(it);
        --IPSecSA_number;
        std::cout << "destoryIPSecSA success!spi:" << spi << std::endl;
        return true;
    }
    else
    {
        // ������
        std::cerr << "destoryIPSecSA failed!Unable to find ipsec sa:" << spi << std::endl;
    }
    return false;
}

bool SAManager::registerIKESA(uint32_t sourceip, uint32_t desip, uint64_t spiI, uint64_t spiR)
{

    IKE_SPI Spitemple;
    Spitemple.spi_i = spiI;
    Spitemple.spi_r = spiR;

    // ���IKESA�Ƿ��Ѵ���
    if (IKE_SACache.find(Spitemple) != IKE_SACache.end())
    {
        std::cout << "Found IKE SA!" << std::endl;
        return false;
    }
    // �����µ�IKE_SAData���󲢲���ӳ��
    IKE_SAData newSAData;
    newSAData.sourceip_ = sourceip;
    newSAData.desip_ = desip;
    newSAData.spiI_ = spiI;
    newSAData.spiR_ = spiR;
    // ������𷽵�ַ���Ǳ���QKI��ַ������Ϊ���𷽣�������Ϊ������
    newSAData.is_initiator = (sourceip == LOCAL_QKI_IPADDRESS ? true : false);
    newSAData.session_id_ = globalSAManager.mapSpiToSessionId(Spitemple); // ʹ��thisָ����ó�Ա����
    if (!connect_KM(newSAData))
    {
        std::cerr << "connect km error" << std::endl;
        return false;
    }
    // �ж��Ƿ���������
    if (newSAData.is_initiator)
    {
        // ����������˴���KM�ĻỰ�������˲���Ҫ��ǰ�򿪻Ự����������KM��
        if (!opensession(newSAData))
        {
            std::cerr << "open session error" << std::endl;
            return false;
        }
    }
    IKE_SACache[Spitemple] = newSAData;
    return true;
}

std::string SAManager::getIKESAKey(uint64_t spiI, uint64_t spiR, uint32_t seq, uint16_t request_len)
{
    IKE_SPI Spitemple;
    Spitemple.spi_i = spiI;
    Spitemple.spi_r = spiR;
    auto it = IKE_SACache.find(Spitemple);
    if (it != IKE_SACache.end())
    {
        // �����ҵ�����Կ
        int useful_size = it->second.keybuffer.size() - it->second.index_;
        while (useful_size < request_len)
        {
            // ������Կ
            if (!addKey(it->second))
            {
                // ������
                std::cerr << "add ikecsa key failed." << std::endl;
                return "";
            }
            useful_size = it->second.keybuffer.size() - it->second.index_;
        }
        std::string returnkeyvalue(it->second.keybuffer.begin() + it->second.index_, it->second.keybuffer.begin() + it->second.index_ + request_len);
        it->second.index_ += request_len;
        return returnkeyvalue;
    }
    return ""; // ���δ�ҵ�spi�����ؿ��ַ���
}

bool SAManager::destoryIKESA(uint64_t spiI, uint64_t spiR)
{
    IKE_SPI Spitemple;
    Spitemple.spi_i = spiI;
    Spitemple.spi_r = spiR;
    auto it = IKE_SACache.find(Spitemple);
    if (it != IKE_SACache.end())
    {
        closesession(it->second); // TODO:����֪ͨ�ر���KM�ĻỰ
        IKE_SACache.erase(it);
        std::cout << "destoryIKESA success!spi:" << spiI << " and " << spiR << std::endl;
        return true;
    }
    else
    {
        // ������
        std::cerr << "destoryIKESA failed!Unable to find spi:" << spiI << " and " << spiR << std::endl;
    }
    return false;
}
