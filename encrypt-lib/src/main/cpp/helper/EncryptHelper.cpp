//
// Created by u51 on 2018/4/25.
//

#include <stdio.h>
#include <string.h>
#include "EncryptHelper.h"
#include "openssl/pem.h"
#include "openssl/md5.h"
#include "JNIHelper.h"

jstring EncryptHelper::encryptByMD5(JNIEnv *env, jstring content)
{
    const char *unicodeChar = env->GetStringUTFChars(content, NULL);
    size_t unicodeCharLength = env->GetStringLength(content);

    unsigned char md[MD5_DIGEST_LENGTH];
    int i;
    char buf[33] = {'\0'};
    MD5((unsigned char*)unicodeChar, unicodeCharLength, (unsigned char*)&md);
    for (i = 0; i < 16; i++) {
        sprintf(&buf[i*2], "%02x", md[i]);
    }
    env->ReleaseStringUTFChars(content, unicodeChar);
    return env->NewStringUTF(buf);
}

jstring EncryptHelper::encryptByAES(JNIEnv *env, jstring aesSecret, jstring content)
{
    /*const char *str = env->GetStringUTFChars(content, 0);
    LOGI("encryptByAES content：%s", str);
    env->ReleaseStringUTFChars(content, str);*/

    const unsigned char *iv = (const unsigned char *) "0123456789012345";
    jbyteArray contentArray = JNIHelper::jstringTojbyteArray(env, content);
    jbyteArray aesSecretArray = JNIHelper::jstringTojbyteArray(env, aesSecret);
    jbyte *encryptKeys = env->GetByteArrayElements(aesSecretArray, NULL);
    jbyte *encryptData = env->GetByteArrayElements(contentArray, NULL);
    jsize src_Len = env->GetArrayLength(contentArray);

    int outlen = 0, cipherText_len = 0;

    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);
    //清空内存空间
    memset(out, 0, (src_Len / 16 + 1) * 16);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    //指定加密算法，初始化加密key/iv
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) encryptKeys, iv);
    //对数据进行加密运算
    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) encryptData, src_Len);
    cipherText_len = outlen;

    //结束加密运算
    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
    cipherText_len += outlen;

    EVP_CIPHER_CTX_cleanup(&ctx);

    env->ReleaseByteArrayElements(aesSecretArray, encryptKeys, 0);
    env->ReleaseByteArrayElements(contentArray, encryptData, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_len);
    env->SetByteArrayRegion(cipher, 0, cipherText_len, (jbyte *) out);
    free(out);

    jclass strClass = env->FindClass("java/lang/String");
    jmethodID methodId = (env)->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
    jstring encoding = env->NewStringUTF("utf-8");
    jstring contentAES = (jstring)env->NewObject(strClass, methodId, cipher, encoding);
    return contentAES;
}

jbyteArray EncryptHelper::encryptDataByAES(JNIEnv *env, jbyteArray aesSecret, jbyteArray content)
{
    LOGI("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    const unsigned char *iv = (const unsigned char *) "0123456789012345";
    jbyte *keys = env->GetByteArrayElements(aesSecret, NULL);
    jbyte *src = env->GetByteArrayElements(content, NULL);
    jsize src_Len = env->GetArrayLength(content);

    int outlen = 0, cipherText_len = 0;

    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);
    //清空内存空间
    memset(out, 0, (src_Len / 16 + 1) * 16);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    LOGI("AES->指定加密算法，初始化加密key/iv");
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) keys, iv);
    LOGI("AES->对数据进行加密运算");
    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) src, src_Len);
    cipherText_len = outlen;

    LOGI("AES->结束加密运算");
    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
    cipherText_len += outlen;

    LOGI("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(&ctx);

    LOGI("AES->从jni释放数据指针");
    env->ReleaseByteArrayElements(aesSecret, keys, 0);
    env->ReleaseByteArrayElements(content, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_len);
    LOGI("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_len, (jbyte *) out);
    LOGI("AES->释放内存");
    free(out);

    return cipher;
}

jstring EncryptHelper::decodeByAES(JNIEnv *env, jstring aesSecret, jstring content)
{
    jbyteArray contentArray = JNIHelper::jstringTojbyteArray(env, content);
    jbyteArray aesSecretArray = JNIHelper::jstringTojbyteArray(env, aesSecret);

    const unsigned char *iv = (const unsigned char *) "0123456789012345";
    jbyte *encryptKey = env->GetByteArrayElements(aesSecretArray, NULL);
    jbyte *encryptData = env->GetByteArrayElements(contentArray, NULL);
    jsize src_Len = env->GetArrayLength(contentArray);

    int outlen = 0, plaintext_len = 0;

    unsigned char *out  = (unsigned char *) malloc(src_Len);
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    //指定解密算法，初始化解密key/iv
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) encryptKey, iv);
    //对数据进行解密运算
    EVP_DecryptUpdate(&ctx, out, &outlen, (const unsigned char *) encryptData, src_Len);
    plaintext_len = outlen;

    //结束解密运算
    EVP_DecryptFinal_ex(&ctx, out + outlen, &outlen);
    plaintext_len += outlen;

    EVP_CIPHER_CTX_cleanup(&ctx);

    env->ReleaseByteArrayElements(aesSecretArray, encryptKey, 0);
    env->ReleaseByteArrayElements(contentArray, encryptData, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_len);
    env->SetByteArrayRegion(cipher, 0, plaintext_len, (jbyte *) out);
    free(out);

    jclass strClass = env->FindClass("java/lang/String");
    jmethodID methodId = (env)->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
    jstring encoding = env->NewStringUTF("utf-8");
    return (jstring)env->NewObject(strClass, methodId, cipher, encoding);
}

jstring EncryptHelper::encryptByRSA(JNIEnv *env, jstring publicKey, jstring content)
{

}

jstring EncryptHelper::decodeByRSA(JNIEnv *env, jstring privateKey, jstring content)
{

}