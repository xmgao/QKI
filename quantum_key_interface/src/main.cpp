#include "packet/packets.hpp"
#include "server.hpp"
#include "samanagement.hpp"
#include "handler.hpp"
#include <thread>
#include <cstdlib> // for std::atoi

// 全局sessionManager实例
SAManager globalSAManager;

// 创建并注册消息处理器
MessageHandlerRegistry global_registry;

uint32_t LOCAL_QKI_IPADDRESS = 0;
uint32_t REMOTE_QKI_IPADDRESS = 0;
const int LISTEN_PORT_QKI = 50001;
int KM_LISTEN_PORT = 50000;

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <local_qki IP address> <remote_qki IP address>" << std::endl;
        return 1;
    }

    std::string local_qki_ipAddress = argv[1];
    std::string remote_qki_ipAddress = argv[2];
    LOCAL_QKI_IPADDRESS = IpStringTouint32(local_qki_ipAddress);
    REMOTE_QKI_IPADDRESS = IpStringTouint32(remote_qki_ipAddress);

    std::cout << "begin register!" << std::endl;
    global_registry.registerHandler(PacketType::REGISTERIKESA, handleRegisterIKESAPacket);
    global_registry.registerHandler(PacketType::GETKEYIKESA, handleIKESAKeyRequestPacket);
    global_registry.registerHandler(PacketType::DESTORYIKESA, handleDestroyIKESAPacket);
    global_registry.registerHandler(PacketType::REGISTERIPSECSA, handleRegisterIPSECSAPacket);
    global_registry.registerHandler(PacketType::GETKEYIPSECSA, handleIPSECSAKeyRequestPacket);
    global_registry.registerHandler(PacketType::DESTORYIPSECSA, handleDestroyIPSECSAPacket);
    global_registry.registerHandler(PacketType::MSG_TYPE_UNKNOWN, handleUnknownPacket);

    // 一个主调度器，用函数指针和回调函数的形式分发处理任务
    Server server1(LISTEN_PORT_QKI);
    std::cout << "begin server1.run!" << std::endl;
    server1.run();

    return 0;
}