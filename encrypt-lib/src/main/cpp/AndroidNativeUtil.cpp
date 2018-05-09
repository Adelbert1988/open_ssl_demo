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


JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_getMD5Content(JNIEnv *env, jobject thiz, jstring srcjStr) {
    return EncryptHelper::encryptByMD5(env, srcjStr);
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_encryptByAES(JNIEnv *env, jobject thiz, jstring secret, jstring srcjStr) {
    return EncryptHelper::encryptByAES(env, secret, srcjStr);
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_decryptByAES(JNIEnv *env, jobject thiz, jstring secret, jstring srcjStr) {
    return EncryptHelper::decryptByAES(env, secret, srcjStr);
}

JNIEXPORT jbyteArray JNICALL Java_com_security_openssl_OpenSslUtil_encryptDataAES(JNIEnv *env, jobject thiz, jbyteArray secret, jbyteArray srcjStr) {
    return EncryptHelper::encryptDataByAES(env, secret, srcjStr);
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_encryptByRSA(JNIEnv *env, jobject thiz, jstring publicKey, jstring content) {
    //jstring 转 char*
    char *base64PublicKeyChars = (char *) env->GetStringUTFChars(publicKey, NULL);
    //char* 转 string
    string base64PublicKeyString = string(base64PublicKeyChars);
    //释放
    env->ReleaseStringUTFChars(publicKey, base64PublicKeyChars);
    //jstring 转 char*
    char *contentChars = (char *) env->GetStringUTFChars(content, NULL);
    //char* 转 string
    string contentString = string(contentChars);
    //释放
    env->ReleaseStringUTFChars(content, contentChars);
    //调用RSA加密函数加密
    string rsaResult = EncryptHelper::encryptByRSA(base64PublicKeyString, contentString);
    //LOGI("rsa result: %s", rsaResult.c_str());
    if (rsaResult.empty()) {
        return NULL;
    }
    //将密文进行base64
    string base64RSA = EncryptHelper::encodeBase64(rsaResult);
    if (base64RSA.empty()) {
        return NULL;
    }
    //string -> char* -> jstring 返回
    //jstring result = env->NewStringUTF(rsaResult.c_str());
    jstring result = env->NewStringUTF(base64RSA.c_str());
    return result;
}

JNIEXPORT jstring JNICALL Java_com_security_openssl_OpenSslUtil_decryptByRSA(JNIEnv *env, jobject thiz, jstring privateKey, jstring content) {
    char *base64PrivateKeyChars = (char *) env->GetStringUTFChars(privateKey, NULL);
    string base64PrivateKeyString = string(base64PrivateKeyChars);

    char *contentChars = (char *) env->GetStringUTFChars(content, NULL);
    string contentString = string(contentChars);

    string decodeBase64RSA = EncryptHelper::decodeBase64(contentString);
    //LOGI("decodeBase64RSA: %s", decodeBase64RSA.c_str());
    string origin = EncryptHelper::decryptByRSA(base64PrivateKeyString, decodeBase64RSA);
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
