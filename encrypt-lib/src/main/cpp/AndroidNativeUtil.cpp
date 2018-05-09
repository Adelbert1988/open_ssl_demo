//
// Created by u51 on 2018/4/17.
//

#include <jni.h>
#include <string>
#include <android/log.h>
#include <string.h>
#include "AndroidNativeUtil.h"
#include "helper/JNIHelper.h"
#include "helper/EncryptHelper.h"

using namespace std;
#ifdef __cplusplus
extern "C" {
#endif


JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_getMD5Content(JNIEnv *env, jobject thiz
        , jstring srcjStr) {
    return EncryptHelper::encryptByMD5(env, srcjStr);
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_encryptByAES(JNIEnv *env, jobject thiz
        , jstring secret, jstring content) {
    char *secretKeyChars = (char *) env->GetStringUTFChars(secret, NULL);
    string secretKeyString = string(secretKeyChars);
    env->ReleaseStringUTFChars(secret, secretKeyChars);

    char *contentChars = (char *) env->GetStringUTFChars(content, NULL);
    string contentString = string(contentChars);
    env->ReleaseStringUTFChars(content, contentChars);

    string aesContent = EncryptHelper::encryptByAES(secretKeyChars, contentString);
    //LOGI("aesContent: %s", aesContent.c_str());
    if (aesContent.empty()) {
        return NULL;
    }
    //将密文进行base64
    string base64RSA = EncryptHelper::encodeBase64(aesContent);
    if (base64RSA.empty()) {
        return NULL;
    }

    jstring result = env->NewStringUTF(base64RSA.c_str());
    return result;
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_decryptByAES(JNIEnv *env, jobject thiz
        , jstring secret, jstring cipherContent) {

    char *secretKeyChars = (char *) env->GetStringUTFChars(secret, NULL);
    string secretKeyString = string(secretKeyChars);
    env->ReleaseStringUTFChars(secret, secretKeyChars);

    char *contentChars = (char *) env->GetStringUTFChars(cipherContent, NULL);
    string cipherContentString = string(contentChars);
    env->ReleaseStringUTFChars(cipherContent, contentChars);

    string decodeBase64AES = EncryptHelper::decodeBase64(cipherContentString);
    //LOGI("decodeBase64AES: %s", decodeBase64AES.c_str());
    string origin = EncryptHelper::decryptByAES(secretKeyString, decodeBase64AES);
    if (origin.empty()) {
        return NULL;
    }

    //LOGI("origin: %s", origin.c_str());
    jstring result = env->NewStringUTF(origin.c_str());
    return result;
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_encryptByRSA(JNIEnv *env, jobject thiz
        , jstring publicKey, jstring content) {

    char *publicKeyChars = (char *) env->GetStringUTFChars(publicKey, NULL);
    string publicKeyString = string(publicKeyChars);
    env->ReleaseStringUTFChars(publicKey, publicKeyChars);

    char *contentChars = (char *) env->GetStringUTFChars(content, NULL);
    string contentString = string(contentChars);
    env->ReleaseStringUTFChars(content, contentChars);

    string rsaResult = EncryptHelper::encryptByRSA(publicKeyString, contentString);
    //LOGI("rsa result: %s", rsaResult.c_str());
    if (rsaResult.empty()) {
        return NULL;
    }
    //将密文进行base64
    string base64RSA = EncryptHelper::encodeBase64(rsaResult);
    if (base64RSA.empty()) {
        return NULL;
    }

    jstring result = env->NewStringUTF(base64RSA.c_str());
    return result;
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_decryptByRSA(JNIEnv *env, jobject thiz
        , jstring privateKey, jstring cipherContent) {

    char *privateKeyChars = (char *) env->GetStringUTFChars(privateKey, NULL);
    string privateKeyString = string(privateKeyChars);
    env->ReleaseStringUTFChars(privateKey, privateKeyChars);

    char *contentChars = (char *) env->GetStringUTFChars(cipherContent, NULL);
    string contentString = string(contentChars);
    env->ReleaseStringUTFChars(cipherContent, contentChars);

    string decodeBase64RSA = EncryptHelper::decodeBase64(contentString);
    //LOGI("decodeBase64RSA: %s", decodeBase64RSA.c_str());
    string origin = EncryptHelper::decryptByRSA(privateKeyString, decodeBase64RSA);
    if (origin.empty()) {
        return NULL;
    }
    //LOGI("origin: %s", origin.c_str());
    jstring result = env->NewStringUTF(origin.c_str());
    return result;
}

//Android和Native交互类
static const char* jClass="com/security/openssl/OpenSslUtil";

//Android和Native交互方法
static JNINativeMethod NativeMethods[] = {/*{ "getMD5Content", "(Ljava/lang/String;)Ljava/lang/String;", (void*)getMD5Content}
        ,{ "encryptAESContent", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)encryptAESContent}
        ,{ "decodeAESContent", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)decodeAESContent}
        ,{ "encryptDataAES", "([B[B)[B", (void*)encryptDataAES}*/};


//动态注册本地方法
static int registerNatives(JNIEnv* env) {
    jclass clazz;
    clazz = (*env).FindClass(jClass);
    if (clazz == NULL)
        return JNI_FALSE;
    if (((*env).RegisterNatives(clazz, NativeMethods, sizeof(NativeMethods) / sizeof(NativeMethods[0])) < 0)) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    jint result = -1;
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return result;
    }

    if (JNIHelper::verifySign(env) == JNI_OK) {
        /*if (registerNatives(env) != JNI_TRUE) {
            return result;
        }*/

        LOGI("签名验证成功");
        return JNI_VERSION_1_4;
    }
    LOGE("签名不一致!");
    return JNI_ERR;
}


#ifdef __cplusplus
}
#endif
