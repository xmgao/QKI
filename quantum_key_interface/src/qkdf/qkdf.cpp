#include "qkdf/qkdf.hpp"
#include "debuglevel.hpp"

const int CounterPayloadSize = 8;

QKDF::QKDF()
    : hashAlg(HashAlg::AlgSHA256), BlockSize(0),
      Period(std::chrono::milliseconds(0)), Rate(0), MR(0), Round(0),
      Epsilon(0.0), Delta(0.0), Name("Default")
{
}

QKDF::~QKDF()
{
}

void QKDF::SetName(const std::string &name)
{
    std::string tempName = name; // 用一个可修改的临时变量来接收输入
    if (tempName.empty())        // 使用empty()来判断是否为空
    {
        tempName = "qkdf";
    }
    this->Name = tempName; // 将修改后的名称赋给成员变量
}

void QKDF::Reset(const byte &iv, const byte &ctx)
{
    this->BlockSize = GetblockSize(this->hashAlg);
    this->Round = 0;
    this->mdk.resize(this->BlockSize);                      // initial by 0；
    this->ctx.resize(this->BlockSize - CounterPayloadSize); // initial by 0；

    this->MR = (uint64_t)std::ceil((this->Rate) * (this->Period.count() / 1000.0) / (this->BlockSize)); // seconds

    if (!iv.empty())
    {
        auto copy_size = std::min(iv.size(), static_cast<size_t>(this->BlockSize));
        std::copy(iv.begin(), iv.begin() + copy_size, this->mdk.begin());
    }

    if (!ctx.empty())
    {
        auto copy_size = std::min(ctx.size(), static_cast<size_t>(this->BlockSize - CounterPayloadSize));
        std::copy(ctx.begin(), ctx.begin() + copy_size, this->ctx.begin());
    }
}

uint64_t QKDF::SecureMR(int key_len)
{
    key_len = 8 * key_len; // bit
    FloatType a_part = pow(2, -key_len);
    FloatType h_part = pow(2, -this->BlockSize * 8);

    if (key_len < this->BlockSize * 8)
    {
        a_part += h_part;
        a_part = sqrt(a_part);
    }

    FloatType tmp_a = this->Epsilon - a_part;
    if (tmp_a < 0)
    {
        return 0;
    }
    FloatType tmp_aa = tmp_a - h_part;
    FloatType tmp_b = pow(2, this->BlockSize * 8 / 2 - 1);
    tmp_b *= tmp_aa;
    uint64_t smr;
    if (tmp_b > 1e+20)
    {
        std::cout << "Error: Value is too large to fit into a uint64_t" << std::endl;
    }
    else
    {
        smr = static_cast<uint64_t>(tmp_b.convert_to<double>());
    }
    return smr;
}

double QKDF::Secure()
{
    FloatType p1 = (FloatType)1 - this->Delta;
    FloatType p2 = p1 * this->Epsilon;
    FloatType s = p1 * p2;
    s += this->Delta;
    double fs = s.convert_to<double>();
    return fs;
}

void QKDF::Extract(byte &key_material)
{
    uint64_t key_material_len = key_material.size();
    byte tmp_mdk;
    if (key_material_len >= static_cast<uint64_t>(this->BlockSize))
    {
        // direct use key_material
        tmp_mdk.resize(this->BlockSize);
        std::copy(key_material.begin(), key_material.begin() + this->BlockSize, tmp_mdk.begin());
    }
    else
    {
        std::string AlgName;
        switch (this->hashAlg)
        {
        case HashAlg::AlgSHA256:
            AlgName.assign("SHA256");
            break;
        case HashAlg::AlgSHA512:
            AlgName.assign("SHA512");
            break;
        default:
            AlgName.assign("SM3");
            break;
        }
        unsigned char *hmac_result = new unsigned char[EVP_MAX_MD_SIZE];
        unsigned int hmac_len;

        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, key_material.data(), key_material_len, EVP_get_digestbyname(AlgName.c_str()), NULL);
        HMAC_Update(ctx, this->mdk.data(), this->mdk.size());
        HMAC_Final(ctx, hmac_result, &hmac_len);
        HMAC_CTX_free(ctx);

        if ((int)hmac_len != this->BlockSize)
        {
            std::cout << "the extract is failed!" << std::endl;
            exit(0);
        }
        tmp_mdk.resize(hmac_len);
        std::copy(hmac_result, hmac_result + hmac_len, tmp_mdk.begin());
        // tmp_mdk = vector<unsigned char>(hmac_result, hmac_result + hmac_len);
        delete[] hmac_result;
    }

    this->mdk = tmp_mdk;
}

byte QKDF::Expend(uint64_t amr)
{
    byte expended, tmp_mdk;
    expended.resize((uint64_t)amr * this->BlockSize); // 输出总密钥流
    tmp_mdk.resize(this->BlockSize);                  // 取出主派生密钥

    memcpy(tmp_mdk.data(), this->mdk.data(), this->BlockSize);

    byte input, counter;
    input.resize(this->BlockSize * 2); // 每轮的输入，前面是前一个的输出+ctx，后面是第j块派生的j
    counter.resize(CounterPayloadSize);
    memcpy(input.data() + this->BlockSize, this->ctx.data(), this->BlockSize - CounterPayloadSize); // ctx
    for (uint64_t i = 1; i <= amr; i++)                                                             // amr轮派生
    {
        std::string AlgName;
        switch (this->hashAlg)
        {
        case HashAlg::AlgSHA256:
            AlgName.assign("SHA256");
            break;
        case HashAlg::AlgSHA512:
            AlgName.assign("SHA512");
            break;
        default:
            AlgName.assign("SM3");
            break;
        }
        HMAC_CTX *hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx, tmp_mdk.data(), this->BlockSize, EVP_get_digestbyname(AlgName.c_str()), NULL);
        // Prepare counter (assuming it's big endian as in Go code)
        uint64_t bigEndianCounter = htobe64(i);
        memcpy(counter.data(), &bigEndianCounter, CounterPayloadSize);

        memcpy(&input[this->BlockSize * 2 - CounterPayloadSize], counter.data(), CounterPayloadSize); // refresh j

        HMAC_Update(hctx, input.data(), this->BlockSize * 2);

        unsigned int len;
        HMAC_Final(hctx, expended.data() + (int)(i - 1) * this->BlockSize, &len);

        if ((int)len != this->BlockSize)
        {
            std::cout << "the output of hmac is not the same as blocksize!" << std::endl;
        }

        HMAC_CTX_free(hctx);

        // // evp
        // EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        // const EVP_MD *md = EVP_get_digestbyname(AlgName.c_str());
        // EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, tmp_mdk.data(), this->BlockSize);
        // EVP_DigestInit_ex(mdctx, md, NULL);
        // EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey);
        // EVP_DigestUpdate(mdctx, input.data(), this->BlockSize * 2);
        // EVP_DigestFinal_ex(mdctx, expended.data() + (int)(i - 1) * this->BlockSize, &len);
        // EVP_MD_CTX_free(mdctx);

        memcpy(input.data(), expended.data() + (int)(i - 1) * this->BlockSize, this->BlockSize); // refresh y_(i-1)
    }
    // for (uint8_t byte : expended) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    // }
    // std::cout << std::endl;
    return expended;
}

byte QKDF::SingleRound(byte &key_material)
{

    // std::string outfilename = "keyfile/" + Name + ".txt";
    // std::ofstream outfile(outfilename, std::ios::app);
    // if (!outfile.is_open())
    // {
    //     // 处理打开文件失败的情况
    //     std::cerr << "Failed to open file: " << outfilename << std::endl;
    // }

    this->Round += 1;
    // outfile << "round " << this->Round << "\textract key " << key_material.size() << std::endl; //

    // Step 1: Extract
    Extract(key_material);

    // Step 2: Decide expand ratio
    uint64_t secure_mr = SecureMR(key_material.size());
    uint64_t actual_mr = std::min(this->MR, secure_mr); // 两个派生倍率取最小
    // outfile << "mr " << this->MR << "\tsmr " << secure_mr << "\tamr " << actual_mr << "\tklen " << key_material.size() << std::endl;

    // Step 3: Expend
    byte expended = Expend(actual_mr);

    // Step 4: Truncate
    uint64_t required = static_cast<uint64_t>(std::floor(static_cast<double>(this->Rate) * this->Period.count() / 1000.0)); // seconds
    // outfile << "truncate key " << "\trequire " << required << "\tgenerate " << expended.size() << std::endl;
    if (required < (uint64_t)expended.size())
    {
        expended.resize(required);
    }

    // outfile << "expended key material-len " << expended.size() << std::endl;
    // for (uint8_t byte : expended)
    // {
    //     outfile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    // }
    // outfile << "\n"
    //         << std::endl; //

    // outfile.close(); // Ensure the file is closed
    return expended;
}

void QKDF::Initialized()
{
    std::ifstream file("config.txt");
    if (!file.is_open())
    {
        std::cerr << "config.txt could not be opened!" << std::endl;
        exit(EXIT_FAILURE); // 改进退出以区分异常退出
    }
    byte ctx;
    std::string name, value;
    while (std::getline(file, name))
    {
        if (name == "period(ms):")
        {
            std::getline(file, value);
            std::istringstream ss(value);
            int period_count;
            ss >> period_count;
            this->Period = std::chrono::milliseconds(period_count);
        }
        else if (name == "hash algorithm:")
        {
            std::getline(file, value);
            if (value == "SM3")
            {
                this->hashAlg = HashAlg::AlgSM3;
            }
            else if (value == "SHA256")
            {
                this->hashAlg = HashAlg::AlgSHA256;
            }
            else
            {
                this->hashAlg = HashAlg::AlgSHA512;
            }
        }
        else if (name == "rate(byte per second):")
        {
            std::getline(file, value);
            std::istringstream ss(value);
            ss >> this->Rate;
        }
        else if (name == "epsilon:")
        {
            std::getline(file, value);
            this->Epsilon = (FloatType)std::stod(value);
        }
        else if (name == "delta:")
        {
            std::getline(file, value);
            this->Delta = (FloatType)std::stod(value);
        }
        else if (name == "context:")
        {
            std::getline(file, value);
            std::string decoded_base64;
            using base64_iterator = boost::archive::iterators::transform_width<
                boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6>;
            std::copy(base64_iterator(value.begin()), base64_iterator(value.end()), std::back_inserter(decoded_base64));
            ctx.assign(decoded_base64.begin(), decoded_base64.end());
        }
    }

    byte nil;
    nil.resize(0);
    Reset(nil, ctx);

    file.close();

    std::string outfilename = "keyfile/" + Name + ".txt";
    std::ofstream outfile(outfilename);
    if (!outfile.is_open())
    {
        // 处理打开文件失败的情况
        std::cerr << "Failed to open file: " << outfilename << std::endl;
    }
    outfile.close(); // Ensure the file is closed
}

int GetblockSize(HashAlg alg)
{
    if (alg == HashAlg::AlgSHA256)
    {
        return SHA256_DIGEST_LENGTH;
    }
    else if (alg == HashAlg::AlgSHA512)
    {
        return SHA512_DIGEST_LENGTH;
    }
    return EVP_MD_size(EVP_sm3());
}
