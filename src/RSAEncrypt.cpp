#include <fstream>
#include <iostream>
#include <openssl/pem.h>
#include <stdio.h>
#include "RSAEncrypt.h"
#include <fstream> 
#include <sstream>
#include "openssl/rsa.h"
#include <string.h>
#include "Variables.h"

RSAEncrypt::RSAEncrypt(){
    this->loadKeys();
}

std::string RSAEncrypt::decryptWithPK(const std::string &message, const std::string & pK)
{
    std::string decrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pK.c_str(), -1);
    RSA* rsa = RSA_new();
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        BIO_free_all(keybio);
        return "LOOOOL";
    }

    int len = RSA_size(rsa);
    char *sub_text = new char[len + 1];
    memset(sub_text, 0, len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    
    int counter = 0;
    while (pos < message.length())
    {
        sub_str = message.substr(pos, len);
        memset(sub_text, 0, len + 1);
        ret = RSA_public_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            decrypt_text.append(std::string(sub_text, ret));
            pos += len;
        }
        counter++;
        if (counter>5000){
            break;
        }
    }

    delete sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);
    
    return decrypt_text;
}

std::string RSAEncrypt::encryptWithSK(const std::string &message, const std::string &sK)
{
    std::string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)sK.c_str(), -1);
    RSA* rsa = RSA_new();
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        BIO_free_all(keybio);
        return "NOTHING!";
    }
    
    int key_len = RSA_size(rsa);
    int block_len = key_len-11;
    
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    int pos = 0;
    std::string sub_str;
    while (pos < message.length())
    {
        sub_str = message.substr(pos, block_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            encrypt_text.append(std::string(sub_text, ret));
        }
        pos += block_len;
    }

    delete sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);
    
    return encrypt_text;
}

std::string RSAEncrypt::encryptWithPK(const std::string &message, const std::string &pK)
{
    std::string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pK.c_str(), -1);
    RSA *rsa = RSA_new();
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

    int key_len = RSA_size(rsa);
    int block_len = key_len - 11;
    
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    int pos = 0;
    std::string sub_str;
    while (pos < message.length())
    {
        sub_str = message.substr(pos, block_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_public_encrypt(sub_str.length(),
        (const unsigned char *)sub_str.c_str(),
        (unsigned char *)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            encrypt_text.append(std::string(sub_text, ret));
        }
        pos += block_len;
    }
    
    BIO_free_all(keybio);
    RSA_free(rsa);
    delete[] sub_text;
    
    return encrypt_text;
}

std::string RSAEncrypt::decryptWithSK(const std::string &message, const std::string &sK)
{
    std::string decrypt_text;
    RSA *rsa = RSA_new();
    BIO *keybio;
    keybio = BIO_new_mem_buf((unsigned char *)sK.c_str(), -1);
    
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (rsa == nullptr)
    {
        return std::string();
    }
    
    int key_len = RSA_size(rsa);
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    int counter = 0;
    while (pos < message.length())
    {
        sub_str = message.substr(pos, key_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_decrypt(
        sub_str.length(), (const unsigned char *)sub_str.c_str(),
        (unsigned char *)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            decrypt_text.append(std::string(sub_text, ret));
            pos += key_len;
        }
        counter++;
        if (counter > 5000)
        {
            break;
        }
    }
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);
    
    return decrypt_text;
}
    
void RSAEncrypt::loadKeys()
{
    std::string path = CERTIFICATES_PATH;
    std::ifstream sKeyRaw(path + "private.pem");
    std::string sKey;
    if (sKeyRaw)
    {
        std::string line;
        while (getline(sKeyRaw, line))
        {
            sKey += line + "\n";
        }
        sKey = sKey.substr(0, sKey.size() - 1);
        this->_secretKey = sKey;
    }
    
    std::ifstream pKeyRaw(path + "public.pem");
    std::string pKey;
    if (pKeyRaw)
    {
        std::string line;
        while (getline(pKeyRaw, line))
        {
            pKey += line + "\n";
        }
        pKey = pKey.substr(0, pKey.size() - 1);
        this->_publicKey = pKey;
    }
}

bool RSAEncrypt::generateKeys()
{
    std::string path = CERTIFICATES_PATH;
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;
    
    int bits = 2048;
    unsigned long e = RSA_F4;
    
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        goto free_all;
    }
    
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1)
    {
        goto free_all;
    }
    
    bp_public = BIO_new_file((path + "public.pem").c_str(), "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if (ret != 1)
    {
        goto free_all;
    }
    
    bp_private = BIO_new_file((path + "private.pem").c_str(), "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    
    free_all:
    
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);
    
    return (ret == 1);
}
