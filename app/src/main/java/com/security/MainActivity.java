package com.security;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.security.openssl.OpenSslUtil;


public class MainActivity extends Activity {


    private static String TAG = "openssl";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String md5Signature = OpenSslUtil.getMD5Content(getSignature());
        Log.i(TAG, "md5 signature: " + md5Signature);

        String content = "thisismaintabactivty";

        String aesContent = OpenSslUtil.encryptAESContent("asdfafasdf", content);
        Log.i(TAG, "aes encrypt Content: " + aesContent);
        String decodeAesContent = OpenSslUtil.decodeAESContent("asdfafasdf", aesContent);
        Log.i(TAG, "aes decode Content: " + decodeAesContent);

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
