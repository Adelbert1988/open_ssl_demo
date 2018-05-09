//
// Created by u51 on 2018/4/25.
//

#ifndef OPEN_SSL_NDK_ENCRYPTHELPER_H
#define OPEN_SSL_NDK_ENCRYPTHELPER_H

#include <jni.h>
#include <string>
#include <string.h>
#include "openssl/pem.h"
#include "openssl/md5.h"
#include "JNIHelper.h"

class EncryptHelper{
public:

    static jstring encryptByMD5(JNIEnv *env, jstring content);

    static std::string encryptByAES(const std::string &aesSecret, const std::string &content);

    static std::string decryptByAES(const std::string &aesSecret, const std::string &cipherContent);

    static std::string encryptByRSA(const std::string &publicKey, const std::string &content);

    static std::string decryptByRSA(const std::string &privateKey, const std::string &cipherContent);

    static std::string encodeBase64(const std::string &decoded_bytes);

    static std::string decodeBase64(const std::string &decoded_bytes);
};

#endif //OPEN_SSL_NDK_ENCRYPTHELPER_H
