#ifndef PACKET_BASE_HPP
#define PACKET_BASE_HPP

#include <iostream>
#include <cstring>
#include <cstdint>
#include <memory>

// 最大的数据长度
#define MAX_BUFFER_SIZE 1024
#define BASE_HEADER_SIZE 4

enum class PacketType : uint16_t
{
    // km具有的包类型
    KEYSUPPLY = 0,
    KEYREQUEST,
    KEYRETURN,
    OPENSESSION,
    CLOSESESSION,
    SESSIONKEYSYNC,
    CONFIRMMESSAGE,
    MSG_TYPE_UNKNOWN,
    // qki具有的包类型
    REGISTERIKESA,
    GETKEYIKESA,
    GETKEYRETURNIKESA,
    DESTORYIKESA,
    REGISTERIPSECSA,
    GETKEYIPSECSA,
    GETKEYRETURNIPSECSA,
    DESTORYIPSECSA
};

// 假设 PacketBase 类已经定义并包含 buffer_ 成员
class PacketBase
{
protected:
    uint8_t *buffer_;
    size_t buffer_size_;

public:
    PacketBase();
    PacketBase(const PacketBase &other);
    PacketBase(PacketBase &&other) noexcept;
    virtual ~PacketBase();

    uint8_t *getBufferPtr();
    size_t getBufferSize() const;
    void setBufferSize(size_t size);
};

using PacketBasePtr = std::shared_ptr<PacketBase>;

#endif