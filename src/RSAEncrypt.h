#ifndef RSAEncrypt_H
#define RSARSAEncrypt_H

#include "openssl/rsa.h"
#include <string>

class RSAEncrypt {
    public:
    RSAEncrypt(); 
    void loadKeys();
    std::string encryptWithPK(const std::string &message, const std::string &pK);
    std::string encryptWithSK(const std::string &message, const std::string &sK);
    std::string decryptWithSK(const std::string &message, const std::string &sK);
    std::string decryptWithPK(const std::string &message, const std::string &pK);
    bool generateKeys(); 
    
    std::string getPK(){ return _publicKey; }
    std::string getSK(){ return _secretKey; }
    
    private:
    std::string _secretKey;
    std::string _publicKey;
};

#endif
