//
// Created by u51 on 2018/4/25.
//

#ifndef OPEN_SSL_NDK_ENCRYPTHELPER_H
#define OPEN_SSL_NDK_ENCRYPTHELPER_H

#include <jni.h>

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

    static jstring decodeByAES(JNIEnv *env, jstring aesSecret, jstring content);

    static jstring encryptByRSA(JNIEnv *env, jstring publicKey, jstring content);

    static jstring decodeByRSA(JNIEnv *env, jstring privateKey, jstring content);
};

#endif //OPEN_SSL_NDK_ENCRYPTHELPER_H
