package com.dspread.cara;

import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.DigestAlgorithm;
import cn.hutool.crypto.digest.Digester;
import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HutoolTest {

    @Test
    public void test() {

        for (int i = 0; i < 2000; i++) {
            new Thread(() -> {

                HttpRequest post = HttpRequest.get("https://localhost:8086/my/get");
                try {
                    HttpResponse execute = post.execute();
                    String body = execute.body();
                    System.out.println(body);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

        }
        try {
            Thread.sleep(1000000000);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    @Test
    public void ada() {
        for (int i = 0; i < 2000; i++) {
            ExecutorService executorService = Executors.newCachedThreadPool();
            executorService.submit(new Thread(() -> {
                try {
                    Thread.sleep(60000);
                } catch (Exception exception) {
                    exception.printStackTrace();
                }

            }));
        }
        try {
            Thread.sleep(1000000000);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    @Test
    public void uuid() {
//        UUID uuid = UUID.randomUUID();
//        String s = DigestUtils.md5Hex(uuid.toString());


        String random = RandomStringUtils.random(24, "0123456789abcdef");
        System.out.println(new BigInteger(random, 16));
    }


    @Test
    public void random() {
        Random random = new Random();
        for (int i = 0; i < 10; i++) {

            BigInteger bigInteger = new BigInteger(new Integer(random.nextInt()).toString());
            BigInteger bigInteger2 = new BigInteger(new Integer(random.nextInt()).toString());
            BigInteger multiply = bigInteger.multiply(new BigInteger("4294967295"));
            BigInteger add = multiply.add(bigInteger2);
            System.out.println(add);
        }
    }

    @Test
    public void pushAPi() {

        HttpRequest post = HttpRequest.post("https://api.jpush.cn/v3/push");
        post.header("Authorization", "Basic NjljNWU3MDcyN2E2YWI5N2MzZmQwZTFkOjFiYjQzY2U5OWUxYTQxMWIxOWFkMmUwMg==");

        post.body("{\n" +
                "   \"platform\": \"all\",\n" +
                "    \"audience\" : {\n" +
                "         \"alias\" : [ \"testAlias\" ]\n" +
                "    },\n" +
                "   \"notification\" : {\n" +
                "      \"alert\" : \"Hi, JPush!\",\n" +
                "      \"android\" : {}, \n" +
                "      \"ios\" : {\n" +
                "         \"extras\" : { \"newsid\" : 321}\n" +
                "      }\n" +
                "   }\n" +
                "}");

        HttpResponse execute = post.execute();
        String body = execute.body();
        System.out.println(body);
    }


    @Test
    void rsa2() {
        try {

            String s = "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";
            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(s.getBytes()));
            PrivateKey aPrivate = keyfactory.generatePrivate(pkcs8EncodedKeySpec);
            String s2 = "1a";
            Signature sha256WithRSA = Signature.getInstance("SHA256WithRSA");
            sha256WithRSA.initSign(aPrivate);
            sha256WithRSA.update(s2.getBytes());
            byte[] sign = sha256WithRSA.sign();
            System.out.println(Arrays.toString(sign));
            System.out.println(sign.length);
            System.out.println(Base64.getEncoder().encodeToString(sign));


//            Sign sign1 = SecureUtil.sign(SignAlgorithm.SHA256withRSA);
//            sign1.sign()

        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    @Test
    void rsa2My() {
        try {

            String s = "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";
            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(s.getBytes()));
            PrivateKey aPrivate = keyfactory.generatePrivate(pkcs8EncodedKeySpec);
            String s2 = "1a";

            Digester digester = new Digester(DigestAlgorithm.SHA256);
            byte[] digest = digester.digest(s2);
            AlgorithmIdentifier sha256Aid = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
            DigestInfo di = new DigestInfo(sha256Aid, digest);
            byte[] encodedDigestInfo = di.toASN1Primitive().getEncoded();

            RSA rsa = new RSA(aPrivate, null);
            byte[] decrypt = rsa.encrypt(s2.getBytes(), KeyType.PrivateKey);
            System.out.println(Arrays.toString(decrypt));
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    @Test
    void adadaaaa() {
//        RandomGenerator randomGenerator = new RandomGenerator("ABCDEF1234567890", 48);
//        String headString = randomGenerator.generate();
//
//        RandomGenerator randomGenerator2 = new RandomGenerator("ABCDEF1234567890", 16);
//        String ad16 = randomGenerator2.generate();
//
//        System.out.println(headString);
//        System.out.println(ad16);

//        RandomGenerator randomGenerator2 = new RandomGenerator("1234567890", 8);
//        String ad8 = randomGenerator2.generate();
//        System.out.println(ad8);
//
//        byte[] encode = Hex.encode("12345678L110002".getBytes());
//        System.out.println(new String(encode));
//        String aaaaa="";
//        try {
//            String s="04669eb685e3eac6f4e4ce958ead7f65886f92437ce3936b02329c06404c5e1e40f191032581c20d266bdb39d4898e78d2e02996c4427dc9aa031af240d6fd93e1b6f894b4dd2405fd16da1463cc593de7fcffd4f4b2d748f9229a3652203d6249";
//            byte[] decode = Hex.decode(s);
//            aaaaa = Base64.getEncoder().encodeToString(decode);
//            System.out.println(aaaaa);
//        } catch (Exception exception) {
//            exception.printStackTrace();
//        }
        Security.addProvider(new BouncyCastleProvider());
        try {
//            final String SIGNALGORITHMS = "SHA256withECDSA";
//            final String ALGORITHM = "EC";
//            final String SECP256K1 = "secp256k1";
//            ECGenParameterSpec ecSpec = new ECGenParameterSpec(SECP256K1);
//            KeyPairGenerator kf = KeyPairGenerator.getInstance(ALGORITHM);
//            kf.initialize(ecSpec, new SecureRandom());
//            KeyPair keyPair = kf.generateKeyPair();
//            PublicKey aPublic = keyPair.getPublic();
//            PrivateKey aPrivate = keyPair.getPrivate();
//            System.out.println(Base64.getEncoder().encodeToString(aPrivate.getEncoded()));
//            System.out.println(Arrays.toString(aPrivate.getEncoded()));
//
//            System.out.println(Base64.getEncoder().encodeToString(aPublic.getEncoded()));
//            System.out.println(Arrays.toString(aPublic.getEncoded()));
//
            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            String s = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEqY3GwOkAbKCu6XcdOBcxpL+Z2iFahxiSp7C94tvsxlLxgIpdmAjMpVBz2FAgOB6K0HopF9crHZpf1W8NpV1pgA==";
            // 执行签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(s.getBytes()));
//            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(s.getBytes()));
            Security.addProvider(new BouncyCastleProvider());

            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            System.out.println(publicKey.toString());

//            String s2="MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEqY3GwOkAbKCu6XcdOBcxpL+Z2iFahxiSp7C94tvsxlLxgIpdmAjMpVBz2FAgOB6K0HopF9crHZpf1W8NpV1pgA==";
//            // 执行签名
//            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(s2.getBytes()));
//            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
//            System.out.println(privateKey.toString());
        } catch (Exception exception) {
            exception.printStackTrace();
        }


    }
}
