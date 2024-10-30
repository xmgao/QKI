#include "packet/packets.hpp"
#include "server.hpp"
#include "samanagement.hpp"
#include "handler.hpp"
#include <thread>
#include <cstdlib> // for std::atoi

// ȫ��sessionManagerʵ��
SAManager globalSAManager;

// ������ע����Ϣ������
MessageHandlerRegistry global_registry;

uint32_t LOCAL_QKI_IPADDRESS = 0;
uint32_t REMOTE_QKI_IPADDRESS = 0;

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
    global_registry.registerHandler(PacketType::REGISTERIPSECSA, handleRegisterIPSECSAPacket);
    global_registry.registerHandler(PacketType::GETKEYIPSECSA, handleIPSECSAKeyRequestPacket);
    global_registry.registerHandler(PacketType::DESTORYIPSECSA, handleDestroyIPSECSAPacket);
    global_registry.registerHandler(PacketType::MSG_TYPE_UNKNOWN, handleUnknownPacket);

    // һ�������������ú���ָ��ͻص���������ʽ�ַ���������
    Server server1(LISTEN_PORT_IPSec);
    std::cout << "begin server1.run!" << std::endl;
    server1.run();

    return 0;
}