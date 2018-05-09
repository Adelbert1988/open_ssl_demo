//
// Created by u51 on 2018/4/18.
//

#include <string>
#include <jni.h>
#include "JNIHelper.h"
#include "EncryptHelper.h"
#include <string.h>

static const char *APP_KEYSTORE_SIGN = "8dd227e710b0cb46a3328693e882c347";


std::string JNIHelper::jstringToString(JNIEnv *env, jstring jstr) {
    if (jstr == nullptr) {
        return "";
    }

    const char* chars = env->GetStringUTFChars(jstr, nullptr);
    std::string ret(chars);
    env->ReleaseStringUTFChars(jstr, chars);

    return ret;
}

jbyteArray JNIHelper::jstringTojbyteArray(JNIEnv *env, jstring jstr) {
    jclass classStr = env->FindClass("java/lang/String");
    jstring encodeType = env->NewStringUTF("utf-8");
    jmethodID mid = env->GetMethodID(classStr, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray barr= (jbyteArray)env->CallObjectMethod(jstr, mid, encodeType);
    env->DeleteLocalRef(classStr);
    env->DeleteLocalRef(encodeType);
    return barr;
}

jobject JNIHelper:: getApplication(JNIEnv *env) {
    jobject application = NULL;
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != NULL) {
        jmethodID currentApplication = env->GetStaticMethodID(
                activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplication != NULL) {
            application = env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
        } else {
            LOGE("Cannot find method: currentApplication() in ActivityThread.");
        }
        env->DeleteLocalRef(activity_thread_clz);
    } else {
        LOGE("Cannot find class: android.app.ActivityThread");
    }

    return application;
}

//so鉴权
int JNIHelper::verifySign(JNIEnv *env) {
    // Application object
    jobject application = JNIHelper::getApplication(env);
    if (application == NULL) {
        return JNI_ERR;
    }

    if (RELEASE_MODE == 1) {
        LOGI("release mode");
    }

    jclass context_clz = env->GetObjectClass(application);
    jmethodID getPackageManager = env->GetMethodID(context_clz
            , "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(application, getPackageManager);
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz
            , "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    jmethodID getPackageName = env->GetMethodID(context_clz
            , "getPackageName", "()Ljava/lang/String;");

    jstring package_name = (jstring) (env->CallObjectMethod(application, getPackageName));
    jobject package_info = env->CallObjectMethod(package_manager, getPackageInfo, package_name, 64);
    jclass package_info_clz = env->GetObjectClass(package_info);
    jfieldID signatures_field = env->GetFieldID(package_info_clz
            , "signatures", "[Landroid/content/pm/Signature;");

    jobject signatures = env->GetObjectField(package_info, signatures_field);
    jobjectArray signatures_array = (jobjectArray) signatures;
    jobject signature0 = env->GetObjectArrayElement(signatures_array, 0);
    jclass signature_clz = env->GetObjectClass(signature0);

    jmethodID toCharsString = env->GetMethodID(signature_clz
            , "toCharsString", "()Ljava/lang/String;");
    // call toCharsString()
    jstring signature_str = (jstring) (env->CallObjectMethod(signature0, toCharsString));
    jstring signature_md5 = EncryptHelper::encryptByMD5(env, signature_str);

    // release
    env->DeleteLocalRef(application);
    env->DeleteLocalRef(context_clz);
    env->DeleteLocalRef(package_manager);
    env->DeleteLocalRef(package_manager_clz);
    env->DeleteLocalRef(package_name);
    env->DeleteLocalRef(package_info);
    env->DeleteLocalRef(package_info_clz);
    env->DeleteLocalRef(signatures);
    env->DeleteLocalRef(signature0);
    env->DeleteLocalRef(signature_clz);
    env->DeleteLocalRef(signature_str);

    const char *sign = env->GetStringUTFChars(signature_md5, NULL);
    if (sign == NULL) {
        LOGE("分配内存失败");
        return JNI_ERR;
    }

    //LOGI("应用中读取到的签名为：%s", sign);
    //LOGI("native中预置的签名为：%s", APP_KEYSTORE_SIGN);
    int result = strcmp(sign, APP_KEYSTORE_SIGN);

    env->ReleaseStringUTFChars(signature_md5, sign);
    env->DeleteLocalRef(signature_md5);
    if (result == 0) {//签名一致
        return JNI_OK;
    }

    return JNI_ERR;
}