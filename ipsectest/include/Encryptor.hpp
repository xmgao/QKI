#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <string>
#include <stdexcept>

class Encryptor {
public:
    // 使用给定密钥对明文进行加密，返回密文
    static bool encrypt(const std::string& plaintext, const std::string& key, std::string& ciphertext);

    // 使用给定密钥对密文进行解密，返回明文
    static bool decrypt(const std::string& ciphertext, const std::string& key, std::string& plaintext);
};

#endif // ENCRYPTOR_H