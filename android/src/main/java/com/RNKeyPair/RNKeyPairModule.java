package com.RNKeyPair;

import android.util.Base64;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.WritableNativeMap;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class RNKeyPairModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;

    public RNKeyPairModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "RNKeyPair";
    }

    public static String getPrivateKeyPKCS8String(PrivateKey priv) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("DSA");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(priv,
                PKCS8EncodedKeySpec.class);
        byte[] packed = spec.getEncoded();
        String key64 = new String(Base64.encode(packed, 0));

        Arrays.fill(packed, (byte) 0);
        return "-----BEGIN PRIVATE KEY-----\n" + key64 + "\n-----END PRIVATE KEY-----";
    }


    public static String getPublicKeyX509String(PublicKey publ) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("DSA");
        X509EncodedKeySpec spec = fact.getKeySpec(publ,
                X509EncodedKeySpec.class);
        return "-----BEGIN PUBLIC KEY-----\n" +
                new String(Base64.encode(spec.getEncoded(), 0)) +
                "\n-----END PUBLIC KEY-----";
    }

    @ReactMethod
    public void generate(Callback callback)  {
        WritableNativeMap keys = new WritableNativeMap();

        try {

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.genKeyPair();
            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKeyX509 = kf.generatePublic(new X509EncodedKeySpec(publicKey));
            PrivateKey privateKeyPKCS8 = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));

            keys.putString("public", getPublicKeyX509String(publicKeyX509));
            keys.putString("private", getPrivateKeyPKCS8String(privateKeyPKCS8));
        }
        catch(GeneralSecurityException e) { }
        callback.invoke(keys);
    }
}