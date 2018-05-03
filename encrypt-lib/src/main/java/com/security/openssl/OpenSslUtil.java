package com.security.openssl;

/**
 * User: chw
 * Date: 2018/4/13
 */
public class OpenSslUtil {

    static {
        System.loadLibrary("android-encrypt");
    }

    public static native String getMD5Content(String message);

    public static native String encryptAESContent(String secret, String content);

    public static native byte[] encryptDataAES(byte[] secret, byte[] content);

    public static native String decodeAESContent(String secret, String content);

}
