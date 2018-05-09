package com.security.openssl;

/**
 * User: chw
 * Date: 2018/4/13
 */
public class OpenSslUtil {

    static {
        System.loadLibrary("defender");
    }

    public static native String getMD5Content(String message);

    public static native String encryptByAES(String secret, String content);

    public static native String decryptByAES(String secret, String content);

    public static native String encryptByRSA(String publicKey, String content);

    public static native String decryptByRSA(String privateKey, String content);
}
