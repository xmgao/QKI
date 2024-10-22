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

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <remote_qki IP address> <remote_qki_port>" << std::endl;
        return 1;
    }

    std::string remote_qki_ipAddress = argv[1];
    int remote_qki_port = std::atoi(argv[2]);

    // �˿ںŷ�Χ��֤
    if (remote_qki_port <= 0 || remote_qki_port > 65535)
    {
        std::cerr << "Invalid remote_qki_port number. Must be between 1 and 65535." << std::endl;
        return 1;
    }

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