package com.example.cara.utils;

import org.springframework.util.Base64Utils;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RsaUtils {

    public static String parsePriKey(String privateKeyStr){
        KeyFactory kf = null;
        String result="";
        try {
            kf = KeyFactory.getInstance("RSA");
            byte[] keyBytes = Base64Utils.decodeFromString(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            PrivateKey privateKey = kf.generatePrivate(keySpec);
            RSAPrivateKeySpec priv = kf.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(priv.getModulus(), BigInteger.valueOf(65537));
//            PublicKey publicKey = kf.generatePublic(publicKeySpec);
//            System.out.println(publicKey.toString());
//            byte[] encode = Base64Utils.encode(publicKey.getEncoded());
            result = publicKeySpec.getModulus().toString(16).toUpperCase();
//            System.out.println(s1);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }finally {
            return result;
        }

    }
}
