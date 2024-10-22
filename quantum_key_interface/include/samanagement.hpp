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
    std::vector<uint8_t> keybuffer; // ԭʼ��Կ����
    std::vector<uint8_t> keyderive; // ��Կ��������
    uint32_t spi_;
    uint32_t sourceip_;
    uint32_t desip_;
    int index_ = 0;
    int KM_fd_ = -1;
    // ��ʶ����վSA���ǳ�վSA,true�������վSA
    bool is_inbound_;
    // ������Ա�����ڴ洢ʹ�ù���seq�Ķ���
    std::queue<int> usedSeq;
};

class SAManager
{
public:
    // ���캯��
    SAManager();

    // ע��SA
    bool registerSA(uint32_t sourceip, uint32_t desip, uint32_t spi, bool is_inbound);

    // ��ȡ��Կ��ͨ��request��ȡ
    std::string getKey(uint32_t spi, uint32_t seq, uint16_t request_len);

    // ɾ���Ự��ͨ��session_idɾ��
    bool destorySA(uint32_t spi);

private:
    std::mutex mutex_;
    // ����spi��SAData��ӳ��
    std::unordered_map<uint32_t, SAData> SACache_;
    // ����ȫ��sa����
    int SA_number;
};

#endif // SAMANAGEMENT_HPP