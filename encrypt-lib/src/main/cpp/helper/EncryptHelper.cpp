//
// Created by u51 on 2018/4/25.
//

#include "EncryptHelper.h"

using std::string;

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

std::string EncryptHelper::encryptByAES(const std::string &aesSecret, const std::string &content)
{
    const unsigned char *iv = (const unsigned char *) "0123456789012345";
    jsize src_Len = content.size();

    int outlen = 0, cipherText_len = 0;

    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);
    //清空内存空间
    memset(out, 0, (src_Len / 16 + 1) * 16);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    //指定加密算法，初始化加密key/iv
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) aesSecret.c_str(), iv);
    //对数据进行加密运算
    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) content.c_str(), src_Len);
    cipherText_len = outlen;

    //结束加密运算
    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
    cipherText_len += outlen;

    EVP_CIPHER_CTX_cleanup(&ctx);

    static std::string result((char *) out, cipherText_len);
    free(out);

    return result;
}

std::string EncryptHelper::decryptByAES(const std::string &aesSecret, const std::string &cipherContent)
{
    const unsigned char *iv = (const unsigned char *) "0123456789012345";
    jsize src_Len = cipherContent.size();

    int outlen = 0, plaintext_len = 0;

    unsigned char *out  = (unsigned char *) malloc(src_Len);
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    //指定解密算法，初始化解密key/iv
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) aesSecret.c_str(), iv);
    //对数据进行解密运算
    EVP_DecryptUpdate(&ctx, out, &outlen, (const unsigned char *) cipherContent.c_str(), src_Len);
    plaintext_len = outlen;

    //结束解密运算
    EVP_DecryptFinal_ex(&ctx, out + outlen, &outlen);
    plaintext_len += outlen;

    EVP_CIPHER_CTX_cleanup(&ctx);

    static std::string result((char *) out, plaintext_len);
    free(out);
    return result;
}

std::string EncryptHelper::encryptByRSA(const std::string &publicKey, const std::string &content) {
    BIO *bio = NULL;
    RSA *rsa_public_key = NULL;
    //从字符串读取RSA公钥串
    if ((bio = BIO_new_mem_buf((void *) publicKey.c_str(), -1)) == NULL) {
        LOGI("BIO_new_mem_buf failed!");
        return "";
    }
    //读取公钥
    rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    //异常处理
    if (rsa_public_key == NULL) {
        //资源释放
        BIO_free_all(bio);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }
    //rsa模的位数
    int rsa_size = RSA_size(rsa_public_key);
    //RSA_PKCS1_PADDING 最大加密长度 为 128 -11
    //RSA_NO_PADDING 最大加密长度为  128
    //rsa_size = rsa_size - RSA_PKCS1_PADDING_SIZE;
    //动态分配内存，用于存储加密后的密文
    unsigned char *to = (unsigned char *) malloc(rsa_size + 1);
    //填充0
    memset(to, 0, rsa_size + 1);
    //明文长度
    int flen = content.length();
    //加密，返回值为加密后的密文长度，-1表示失败
    int status = RSA_public_encrypt(flen
            , (const unsigned char *) content.c_str()
            , to
            , rsa_public_key, RSA_PKCS1_PADDING);

    //异常处理
    if (status < 0) {
        //资源释放
        free(to);
        BIO_free_all(bio);
        RSA_free(rsa_public_key);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }
    //赋值密文
    static std::string result((char *) to, status);
    free(to);
    BIO_free_all(bio);
    RSA_free(rsa_public_key);
    CRYPTO_cleanup_all_ex_data();
    return result;
}


std::string EncryptHelper::decryptByRSA(const std::string &privateKey, const std::string &cipherContent) {
    BIO *bio = NULL;
    RSA *rsa_private_key = NULL;
    //从字符串读取RSA公钥串
    if ((bio = BIO_new_mem_buf((void *) privateKey.c_str(), -1)) == NULL) {
        LOGI("BIO_new_mem_buf failed!");
        return "";
    }
    //读取私钥
    rsa_private_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    //异常处理
    if (rsa_private_key == NULL) {
        //资源释放
        BIO_free_all(bio);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }
    //rsa模的位数
    int rsa_size = RSA_size(rsa_private_key);
    //动态分配内存，用于存储解密后的明文
    unsigned char *to = (unsigned char *) malloc(rsa_size + 1);
    //填充0
    memset(to, 0, rsa_size + 1);
    //密文长度
    int flen = cipherContent.length();
    // RSA_NO_PADDING
    // RSA_PKCS1_PADDING
    //解密，返回值为解密后的名文长度，-1表示失败
    int status = RSA_private_decrypt(flen, (const unsigned char *) cipherContent.c_str(), to, rsa_private_key,
                                     RSA_PKCS1_PADDING);
    //异常处理率
    if (status < 0) {
        //释放资源
        free(to);
        BIO_free_all(bio);
        RSA_free(rsa_private_key);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }
    //赋值明文，是否需要指定to的长度？
    static std::string result((char *) to);
    //释放资源
    free(to);
    BIO_free_all(bio);
    RSA_free(rsa_private_key);
    //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
    CRYPTO_cleanup_all_ex_data();
    return result;
}

std::string EncryptHelper::encodeBase64(const std::string &decoded_bytes) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    //不换行
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    //encode
    BIO_write(bio, decoded_bytes.c_str(), (int) decoded_bytes.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    //这里的第二个参数很重要，必须赋值
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::string EncryptHelper::decodeBase64(const std::string &encoded_bytes) {
    BIO *bioMem, *b64;
    bioMem = BIO_new_mem_buf((void *) encoded_bytes.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bioMem = BIO_push(b64, bioMem);
    //获得解码长度
    size_t buffer_length = BIO_get_mem_data(bioMem, NULL);
    char *decode = (char *) malloc(buffer_length + 1);
    //填充0
    memset(decode, 0, buffer_length + 1);
    BIO_read(bioMem, (void *) decode, (int) buffer_length);
    static std::string decoded_bytes(decode);
    BIO_free_all(bioMem);
    return decoded_bytes;
}


