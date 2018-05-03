//
// Created by u51 on 2018/4/18.
//
#include <android/log.h>
#include <string>
#ifndef OPEN_SSL_NDK_JNIHELPER_H
#define OPEN_SSL_NDK_JNIHELPER_H
class JNIHelper{
#define RELEASE_MODE 0

#define TAG "openssl"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG ,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG ,__VA_ARGS__)

private:

public:
    static std::string jstringToString(JNIEnv *env, jstring jstr);

    static jbyteArray jstringTojbyteArray(JNIEnv *env, jstring jstr);

    /**
     * 获取安卓application
     * @param env
     * @return
     */
    static jobject getApplication(JNIEnv *env);

    /**
     * 调用鉴权
     * @param env
     * @return
     */
    static int verifySign(JNIEnv *env);

};


#endif //OPEN_SSL_NDK_JNIHELPER_H
