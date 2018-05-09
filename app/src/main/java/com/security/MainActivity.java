package com.security;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import com.security.openssl.OpenSslUtil;


public class MainActivity extends Activity {
    private static final String TEST_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSGCqEF3bOfFHFnyjOu7HHmmIK\n" +
            "a1bsJ8zvpBqZBZp8bsEfXDXU/P35vBNR4fbx7f241ZCBoFE6HIn01ZUgI5H/cy+E\n" +
            "3CvZm4PJBmMkBqP5Z7KL7kDhvvWCYIDhyFpRQ7+bkY+9Sln1WWJRY5ps0OVD+Gr0\n" +
            "BqmcokRn5vCIvO3dewIDAQAB\n" +
            "-----END PUBLIC KEY-----";
    private static final String TEST_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQDSGCqEF3bOfFHFnyjOu7HHmmIKa1bsJ8zvpBqZBZp8bsEfXDXU\n" +
            "/P35vBNR4fbx7f241ZCBoFE6HIn01ZUgI5H/cy+E3CvZm4PJBmMkBqP5Z7KL7kDh\n" +
            "vvWCYIDhyFpRQ7+bkY+9Sln1WWJRY5ps0OVD+Gr0BqmcokRn5vCIvO3dewIDAQAB\n" +
            "AoGBAKalpJPCSOrgkbw/0w6oswuw2bOKERihOV2cvbxDRZcOAwHtEoYvZwWAuZJp\n" +
            "uoeMT4UdYdJwZ/3ARW1/PRqRHGwjxoAYJX/faTt6gGvJpHGhaf1S0DHaMq+Emstl\n" +
            "9L/YlD+bxY6hcrov8R4yd5WMeXQVKckmpO2s8vfH6K35NfABAkEA74Z9wOQPpMEl\n" +
            "acgJjtEgyz4wrcQmB0TZf7P8mj7YBErwXtgOmxCRw0sSmlnVj6q6DrHyTqRbwHUB\n" +
            "M2CX3E/lgQJBAOCLdg3v0N+hBPtqJESHJh12BG/u4c1qK6OvRNTpkZuz5ksKDJJx\n" +
            "Cyq36hDEsCIwXyKLFBNaA5JN65KLqDhz2PsCQQCBkRPXUsavjZdqaD3bVn7R0ltM\n" +
            "s+0KQ5EPxlHfMh1x/QOXmnIUKVtf8+0lN3ERnP22U0XKipfjPKegniCnmUSBAkBn\n" +
            "D5ufyfKUsdMXkiATU/SqkQB4X6xEG/brqgZtssaiMHADARnEHR6C/Obxy1UMXCdO\n" +
            "M4eDWk1JWXpGSNNtFb8BAkBEjj/DPFqoCa9hOQC6deRIYs8G+YGtpxdn46qCirxu\n" +
            "tp85w62MGDVpdvIB3QYweWtAQ9Aw9tCfpUsqtMrsGuNt\n" +
            "-----END RSA PRIVATE KEY-----";

    private static final String AES_KEY = "JA2F8AKJF3D7HF12";
    private static String TAG = "openssl";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String md5Signature = OpenSslUtil.getMD5Content(getSignature());
        //Log.i(TAG, "md5 加密: " + md5Signature);

        String content = "thisismaintabactivty打发撒发生 adasdfasdfadfasdfasdgqwerqwerqwerqwer";
        //String encode64Content = Base64.encodeToString(content.getBytes(), Base64.NO_WRAP);

        String aesContent = OpenSslUtil.encryptByAES(AES_KEY, content);
        Log.i(TAG, "aes 加密: " + aesContent);
        ((TextView)findViewById(R.id.tv_aes)).setText("AES: " + aesContent);

        String decodeAesContent = OpenSslUtil.decryptByAES(AES_KEY, aesContent);
        //byte[] decode64Content = Base64.decode(decodeAesContent, Base64.NO_WRAP);
        Log.i(TAG, "aes 解密: " + new String(decodeAesContent));

        //String rsaContent = OpenSslUtil.encryptByRSA(TEST_PUBLIC_KEY, content);
        //Log.i(TAG, "rsa 加密: " + rsaContent);
        //((TextView)findViewById(R.id.tv_rsa)).setText("RSA: " + rsaContent);
        //String rsaDecrypt = OpenSslUtil.decryptByRSA(TEST_PRIVATE_KEY, rsaContent);
        //Log.i(TAG, "rsa 解密: " + rsaDecrypt);

        //String aesContent2 = new String(OpenSslUtil.encryptDataAES(AES_KEY.getBytes(), content.getBytes()));
        //Log.i(TAG, "aes encrypt byte[] Content: " + aesContent2);
        //Log.i(TAG, "main sign: " + getSignature());
    }


    public String getSignature() {
        try {
            StringBuilder builder = new StringBuilder();
            /** 通过包管理器获得指定包名包含签名的包信息 **/
            PackageInfo packageInfo = getPackageManager().getPackageInfo(getPackageName()
                    , PackageManager.GET_SIGNATURES);
            /******* 通过返回的包信息获得签名数组 *******/
            Signature[] signatures = packageInfo.signatures;
            /******* 循环遍历签名数组拼接应用签名 *******/
            for (Signature signature : signatures) {
                builder.append(signature.toCharsString());
            }
            /************** 得到应用签名 **************/
            return builder.toString();
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }

        return "";
    }
}
