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
    /**
     * md5数据加密
     * @param env
     * @param content
     * @return
     */
    static jstring encryptByMD5(JNIEnv *env, jstring content);

    static jstring encryptByAES(JNIEnv *env, jstring aesSecret, jstring content);

    static jbyteArray encryptDataByAES(JNIEnv *env, jbyteArray aesSecret, jbyteArray content);

    static jstring decryptByAES(JNIEnv *env, jstring aesSecret, jstring content);

    static std::string encryptByRSA(const std::string &publicKey, const std::string &content);

    static std::string decryptByRSA(const std::string &privateKey, const std::string &content);

    static std::string encodeBase64(const std::string &decoded_bytes);

    static std::string decodeBase64(const std::string &decoded_bytes);
};

#endif //OPEN_SSL_NDK_ENCRYPTHELPER_H
