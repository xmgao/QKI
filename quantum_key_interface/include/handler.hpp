#ifndef HANDLER_HPP
#define HANDLER_HPP

#include "packet/packetbase.hpp"
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <map>

// ����ָ�����Ͷ��壨ÿ�������������ļ���������������Ϣ��
typedef void (*MessageHandler)(int, PacketBase &);

// ע��͹���ص���������
class MessageHandlerRegistry
{
public:
    void registerHandler(PacketType type, MessageHandler handler)
    {
        handlers[type] = handler;
    }

    MessageHandler getHandler(PacketType type) const
    {
        auto it = handlers.find(type);
        if (it != handlers.end())
        {
            return it->second;
        }
        return nullptr;
    }

private:
    std::map<PacketType, MessageHandler> handlers;
};

// ����ע��IPSECSA
void handleRegisterIPSECSAPacket(int fd, PacketBase &pkt1);

// ����IPSECSA��Կ����
void handleIPSECSAKeyRequestPacket(int fd, PacketBase &pkt1);

// ��������IPSECSA
void handleDestroyIPSECSAPacket(int fd, PacketBase &pkt1);

// ����ע��IKESA
void handleRegisterIKESAPacket(int fd, PacketBase &pkt1);

// ����IKESA��Կ����
void handleIKESAKeyRequestPacket(int fd, PacketBase &pkt1);

// ��������IKESA
void handleDestroyIKESAPacket(int fd, PacketBase &pkt1);

// ����UNKOWN_TYPE
void handleUnknownPacket(int fd, PacketBase &pkt);
// ģ�����Ϣ�н���������
PacketType parsePacketType(uint16_t type);

#endif
