#ifndef QKDF_HPP
#define QKDF_HPP

#include <vector>
#include <chrono>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <stdio.h>
#include <chrono>
#include <stdlib.h>
#include <cmath>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <fstream>
#include <mutex>
#include <thread>


using byte = std::vector<uint8_t>;

using FloatType = long double; // Adjust precision as needed

enum class HashAlg : int
{
    AlgSM3,
    AlgSHA256,
    AlgSHA512,
};

class QKDF
{
public:
    // Constructor
    QKDF();
    ~QKDF();

    HashAlg hashAlg; // Hash algorithm
    int BlockSize;   // Key block size (byte)

    // Member functions
    void Initialized();
    void SetName(const std::string &name);
    void Reset(const byte &iv, const byte &ctx);
    uint64_t SecureMR(int key_len);
    double Secure();
    void Extract(byte &key_material);
    byte Expend(uint64_t amr);
    byte SingleRound(byte &key_material);
    byte SingleRound(byte &key_material, uint64_t request_keylen);

private:
    std::chrono::milliseconds Period; // Sampling period
    uint64_t Rate;                    // Target rate (byte per second)
    uint64_t MR;                      // Multiplier ratio
    uint64_t Round;                   // Current round
    byte mdk;                         // Key material
    byte ctx;                         // Context
    FloatType Epsilon;                // Security threshold
    FloatType Delta;                  // Security level
    std::string Name;                 // Name
};

int GetblockSize(HashAlg alg);

#endif