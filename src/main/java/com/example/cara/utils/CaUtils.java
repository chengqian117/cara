package com.example.cara.utils;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import sun.security.x509.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Matcher;

@Slf4j
public class CaUtils {

    private static final String CREATE_CER_ERROR="cer证书生成发生错误";
    private static final String CREATE_KEYSTORE_ERROR="KeyStore生成发生错误";
    private static final String EXPORT_CER_ERROR="cer证书导出发生错误";
    private static final String ALIAS_EMPTY="alias为空";
    private static final String ALIAS_ERROR="对应alias无证书";
    private static final String PARAM_ERROR="参数异常";

    private static final String DEFAULT_PASSWORD="123456";

    public static final String PATH="D:\\ssl_k\\java";

    /**
     * 通过内置的rsa秘钥对生成秘钥库 默认有效时间三年
     * @param alias cer别名
     * @param password 秘钥库密码 不包含空格 不小于6位
     * @param subject 证书使用者信息
     * @return
     */
    public static KeyStore generateKeyStore(String alias,String password,X500Name subject,X500Name issuer){
        //生成秘钥
        KeyPairGenerator keyPairGenerator= null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        return generateKeyStore(alias,password,aPrivate,aPublic,subject,issuer,1096L);
    }

    /**
     *通过rsa字符串密码生成秘钥库
     * @param alias cer别名
     * @param password 秘钥库密码 不包含空格 不小于6位
     * @param privateKey 私钥
     * @param publicKey 公钥
     * @param subject 证书使用者信息
     * @param validity 有效天数
     * @return
     */
    public static KeyStore generateKeyStore(String alias,String password,String privateKey,String publicKey,X500Name subject,X500Name issuer,long validity){
        try {
            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getBytes()));
            PrivateKey aPrivate = keyfactory.generatePrivate(pkcs8EncodedKeySpec);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey.getBytes()));
            PublicKey aPublic = keyfactory.generatePublic(x509EncodedKeySpec);
            return generateKeyStore(alias,password,aPrivate,aPublic,subject,issuer,validity);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * 通过rsa密码生成秘钥库
     * @param alias cer别名
     * @param password 秘钥库密码 不包含空格 不小于6位
     * @param privateKey 私钥
     * @param publicKey 公钥
     * @param subject 证书使用者信息
     * @param validity 有效天数
     * @return
     */
    public static KeyStore generateKeyStore(String alias,String password,PrivateKey privateKey,PublicKey publicKey,X500Name subject,X500Name issuer,long validity){
        log.info("generateKeyStore ---begin---"+alias);
        if(StringUtils.isEmpty(alias)||StringUtils.isEmpty(password)||password.trim().length()<6||privateKey==null||publicKey==null||subject==null||validity<365){
            log.error(PARAM_ERROR);
            return null;
        }
        if(StringUtils.isEmpty(alias)){
            log.error(ALIAS_EMPTY);
            return null;
        }
        alias=alias.trim();
        try{
//            final long validity = 1096;
            //设置cer内容
            X509CertImpl rootCer = createCer(subject, validity, publicKey,issuer);
            rootCer.sign(privateKey, "SHA256WithRSA");

            final char[] keyPassword = password.toCharArray();
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] =rootCer;
            //加载KeyStore
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(null, null);
            ks.setKeyEntry(alias, privateKey, keyPassword, chain);



            log.info("generateKeyStore ---end---"+alias);
            return ks;
        }catch(Exception exception){
            exception.printStackTrace();
            log.error(CREATE_KEYSTORE_ERROR);
            return null;
        }

    }

    /**
     * 生成并导出秘钥库
     * @param alias cer别名
     * @param password 秘钥库密码 不包含空格 不小于6位
     * @param privateKey 私钥
     * @param publicKey 公钥
     * @param subject 证书使用者信息
     * @param validity 有效天数
     * @param extPath 导出相对根路径路径（-）分割
     * @return
     */
    public static boolean generateAndExportKeyStore(String alias,String password,PrivateKey privateKey,PublicKey publicKey,X500Name subject,X500Name issuer,long validity,String extPath){
        KeyStore keyStore = generateKeyStore(alias, password, privateKey, publicKey, subject,issuer, validity);
        if(keyStore==null){
            return false;
        }
        extPath = initPath(extPath);
        String file=extPath + File.separator + alias + ".p12";
        try{
            exportKeyStore(file,keyStore,password.toCharArray());
        }catch(Exception exception){
            exception.printStackTrace();
            return false;
        }
        return true;
    }

    public static boolean generateAndExportRoot(String alias,String password,X500Name subject,String extPath){
        KeyStore keyStore = generateKeyStore(alias, password, subject,subject);
        if(keyStore==null){
            return false;
        }
        extPath = initPath(extPath);
        String file=extPath + File.separator + alias + ".p12";
        try{
            exportKeyStore(file,keyStore,password.toCharArray());
        }catch(Exception exception){
            exception.printStackTrace();
            return false;
        }
        return true;
    }
    /**
     * 导出cer证书
     * @param alias 证书别名
     * @param extPath 导出相对根路径路径 （-）分割
     * @param parentAlias 父秘钥库名称
     * @param password 秘钥库密码 不包含空格 不小于6位
     * @return
     */
    public static boolean exportCer(String alias,String extPath,String parentAlias,String password){
        log.info("exportCer ---begin---"+alias);
        if(StringUtils.isEmpty(alias)||StringUtils.isEmpty(parentAlias)||StringUtils.isEmpty(password)||password.trim().length()<6){
            log.error(PARAM_ERROR);
            return false;
        }
        try{
            extPath = initPath(extPath);
            FileInputStream in = new FileInputStream(extPath+File.separator+parentAlias+".p12");
            KeyStore ks = KeyStore.getInstance("jks");
            ks.load(in, password.toCharArray());
            java.security.cert.Certificate certificate = ks.getCertificate(alias);
            if(certificate==null){
                log.error(ALIAS_ERROR);
                return false;
            }
            FileOutputStream fop =getOutStream(extPath+File.separator+alias+".cer");
            fop.write(certificate.getEncoded());
            fop.close();
        }catch(Exception exception){
            exception.printStackTrace();
            log.error(EXPORT_CER_ERROR);
            return false;
        }
        log.info("exportCer ---end---"+alias);
        return true;
    }


    /**
     * 导出根CA证书
     * @param alias 根证书别名
     * @param password 根证书密码
     * @return
     */
    public static boolean exportRootCer(String alias,String password){
        return exportCer(alias,"root",alias,StringUtils.isEmpty(password)?DEFAULT_PASSWORD:password);
    }


    /**
     * 封装cer证书信息
     * @param subject 证书使用者信息
     * @param validityDay 有效日期
     * @param publicKey 证书公钥
     * @param issuer 证书颁布者信息
     * @return
     */
    public static X509CertImpl createCer(X500Name subject,long validityDay,PublicKey publicKey,X500Name issuer){
        try{
            //
            Date beginTime = DateUtil.parse("2021-11-16", DatePattern.NORM_DATE_PATTERN);
            long validity = (long) validityDay * 24 * 60 * 60;
            Date endTime =new Date(beginTime.getTime() + validity * 1000L);
            CertificateValidity validityCer = new CertificateValidity(beginTime, endTime);

            X509CertInfo cerInfo = new X509CertInfo();
            cerInfo.set(X509CertInfo.VERSION, new CertificateVersion(2));
//            String random = RandomStringUtils.random(24, "0123456789abcdef");
            BigInteger add =(new BigInteger("1111111111",10));
            cerInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(add));
            AlgorithmId algorithmID = AlgorithmId.get("SHA256WithRSA");
            cerInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmID));
            //颁发给
            cerInfo.set(X509CertInfo.SUBJECT, subject);
            cerInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            cerInfo.set(X509CertInfo.VALIDITY, validityCer);

            //颁发者
            if(issuer!=null){

                cerInfo.set(X509CertInfo.ISSUER, issuer);
            }

            X509CertImpl cer = new X509CertImpl(cerInfo);

            return cer;
        }catch(Exception exception){
            exception.printStackTrace();
//            log.error(CREATE_KEYSTORE_ERROR);
            throw new RuntimeException(CREATE_CER_ERROR);
        }

    }

    /**
     * 封装根cer证书信息
     * @param subject 证书信息
     * @param validityDay 有效日期
     * @param publicKey 证书公钥
     * @return
     */
    public static X509CertImpl createRootCer(X500Name subject,long validityDay,PublicKey publicKey){
        return createCer(subject,validityDay,publicKey,subject);
    }

    /**
     * 导出秘钥库
     * @param file 导出到文件
     * @param ks 秘钥库
     * @param keyPassword 秘钥库密码
     * @throws IOException io异常
     * @throws CertificateException 证书异常
     * @throws KeyStoreException 秘钥库异常
     * @throws NoSuchAlgorithmException NoSuchAlgorithm异常
     */
    public static void exportKeyStore(String file,KeyStore ks ,char[] keyPassword) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        FileOutputStream fop =getOutStream(file);
        ks.store(fop, keyPassword);
        fop.close();
    }

    /**
     * 获取输出流
     * @param filePath 文件路径
     * @return 输出流
     * @throws FileNotFoundException 找不到文件异常
     */
    public static FileOutputStream getOutStream(String filePath) throws FileNotFoundException {
        File file = new File(filePath);
        String path = file.getParent();
        File parent = new File(path);
        if(!parent.exists()){
            boolean mkdirs = parent.mkdirs();
        }
        FileOutputStream fop = new FileOutputStream(file);
        return fop;
    }

    /**
     * 通过相对路径生成绝对路径
     * @param extPath 导出相对根路径路径（-）分割
     * @return
     */
    public static String initPath(String extPath){
        if(StringUtils.isEmpty(extPath)){
            extPath=PATH;
        }else {
            String[] split = extPath.trim().split("-");
            extPath="";
            for (int i = 0; i <split.length ; i++) {
                extPath+=File.separator+split[i];
            }
            extPath=PATH+extPath;
        }
        return extPath;
    }

    public static String normalizePath(String path) {
        String result = path.replaceAll("/+", Matcher.quoteReplacement(File.separator));
        return result.replaceAll("\\\\+", Matcher.quoteReplacement(File.separator));
    }

    public static String splitString(String content, int len) {
        String tmp = "";
        if (len > 0) {
            if (content.length() > len) {
                int rows = (content.length() + len - 1) / len;
                for (int i = 0; i < rows; i++) {
                    if (i == rows - 1) {
                        tmp += content.substring(i * len);
                    }
                    else {
                        tmp += content.substring(i * len, i * len + len) + "\n";
                    }
                }
            }
            else {
                tmp = content;
            }
        }
        return tmp;
    }

}
