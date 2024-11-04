#include "Encryptor.hpp"
#include <iostream>

bool Encryptor::encrypt(const std::string& plaintext, const std::string& key, std::string& ciphertext) {
    // 检查密钥长度是否至少与明文长度相等
    if (key.size() < plaintext.size()) {
        return false; // 密钥长度不足
    }

    ciphertext.resize(plaintext.size());

    // 逐字节异或操作
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext[i] = plaintext[i] ^ key[i];
    }

    return true;
}

bool Encryptor::decrypt(const std::string& ciphertext, const std::string& key, std::string& plaintext) {
    // 检查密钥长度是否至少与密文长度相等
    if (key.size() < ciphertext.size()) {
        return false; // 密钥长度不足
    }

    plaintext.resize(ciphertext.size());

    // 逐字节异或操作
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext[i] = ciphertext[i] ^ key[i];
    }

    return true;
}

int encryptortest() {
    std::string plaintext = "This is a secret message.";
    std::string key = "XQbSZCGMQZZyBqnmekEXfjJzyJw"; // 假设密钥长度至少与明文长度相同。

    std::string ciphertext;
    std::string decryptedtext;

    // 加密
    if (Encryptor::encrypt(plaintext, key, ciphertext)) {
        std::cout << "Ciphertext: ";
        for (const auto &ch : ciphertext) {
            std::cout << std::hex << (int)ch << " ";
        }
        std::cout << std::dec << std::endl; // 恢复十进制格式
    } else {
        std::cerr << "Encryption failed due to insufficient key length." << std::endl;
    }

    // 解密
    if (Encryptor::decrypt(ciphertext, key, decryptedtext)) {
        std::cout << "Decrypted text: " << decryptedtext << std::endl;
    } else {
        std::cerr << "Decryption failed due to insufficient key length." << std::endl;
    }

    return 0;
}