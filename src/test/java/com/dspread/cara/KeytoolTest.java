package com.dspread.cara;

import com.dspread.cara.utils.CaUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import sun.security.pkcs10.PKCS10;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

@Slf4j
public class KeytoolTest {


    @Test
    public void RootTest(){
        String alias="dspreadRoot";
        String password="dspreadpwd";
        final String commonName = "www.dspread.com";
        final String organizationalUnit = "CARA认证中心";
        final String organization = "CARA认证中心";
        final String city = "beijing";
        final String state = "beijing";
        final String country = "CN";
        try{
            X500Name subject = new X500Name(commonName, organizationalUnit, organization, city, state, country);
            CaUtils.generateAndExportRoot(alias,password,subject,"root");
            CaUtils.exportRootCer(alias,password);
        }catch(Exception exception){
            exception.printStackTrace();
        }
    }
    @Test
    public void CaUtilsTest(){
        final String commonName = "cs.dspread.net";
        final String organizationalUnit = "dspread.net";
        final String organization = "dspread.net";
        final String city = "beijing";
        final String state = "beijing";
        final String country = "CN";
        final String root="dspreadRoot";
        // 3 years
        try {
            String alias="dspreadServer";
            String password="dspreadpwd";

            FileInputStream in = new FileInputStream(CaUtils.PATH+"\\root"+File.separator+root+".p12");
            KeyStore ks = KeyStore.getInstance("jks");
            ks.load(in, password.toCharArray());
            java.security.cert.Certificate c1 = ks.getCertificate(root);
            X509CertImpl rootCer = new X509CertImpl(c1.getEncoded());
            X509CertInfo rooCerInfo = (X509CertInfo) rootCer.get(X509CertImpl.NAME +
                    "." + X509CertImpl.INFO);
            PrivateKey privateKey = (PrivateKey) ks.getKey(root, password.toCharArray());


            //b1      -----
            KeyPairGenerator keyPairGenerator= null;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey aPrivate = keyPair.getPrivate();
            PublicKey aPublic = keyPair.getPublic();
            X500Name subject = new X500Name(commonName, organizationalUnit, organization, city, state, country);

            //设置cer内容
            X509CertImpl x509Cert = CaUtils.createCer(subject, 365, aPublic,(X500Name) rooCerInfo.get(X509CertInfo.SUBJECT));

            //client
//            KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
//            keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE,true);
//            keyUsageExtension.set(KeyUsageExtension.KEY_ENCIPHERMENT,true);
//
//            x509Cert.set(X509CertImpl.NAME+"."+X509CertImpl.INFO+"."+X509CertInfo.EXTENSIONS+"."+KeyUsageExtension.NAME,keyUsageExtension);
//
//            Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
//            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1}));
//            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2}));
//            ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);
//
//            x509Cert.set(X509CertImpl.NAME+"."+X509CertImpl.INFO+"."+X509CertInfo.EXTENSIONS+"."+ExtendedKeyUsageExtension.NAME,extendedKeyUsageExtension);
//
//            GeneralNameInterface dnsName = new DNSName("www.c1.com");
//            GeneralName generalName=new GeneralName(dnsName);
//            GeneralNames generalNames = new GeneralNames().add(generalName);
//            SubjectAlternativeNameExtension subjectAlternativeNameExtension = new SubjectAlternativeNameExtension(generalNames);
//            x509Cert.set(SubjectAlternativeNameExtension.IDENT,subjectAlternativeNameExtension);



            //ca
                List<PolicyInformation> list=new ArrayList<>();
                PolicyInformation policyInformation = new PolicyInformation(new CertificatePolicyId(new ObjectIdentifier("2.5.29.32.0")), new HashSet<>());
                list.add(policyInformation);
                CertificatePoliciesExtension certificatePoliciesExtension=new CertificatePoliciesExtension(list);

                x509Cert.set(CertificatePoliciesExtension.IDENT,certificatePoliciesExtension);
                BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(true,0);

                x509Cert.set(BasicConstraintsExtension.IDENT,basicConstraintsExtension);
                KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
                keyUsageExtension.set(KeyUsageExtension.CRL_SIGN,true);
                keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN,true);

                x509Cert.set(KeyUsageExtension.IDENT,keyUsageExtension);

                Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
                objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{2, 5, 29, 37, 0}));
                ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);

                x509Cert.set(ExtendedKeyUsageExtension.IDENT,extendedKeyUsageExtension);


            //

            X509CertInfo x509CertInfo = (X509CertInfo)x509Cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

            x509Cert.sign(privateKey, "SHA256WithRSA");


            final char[] keyPassword = password.toCharArray();
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] =x509Cert;
            //加载KeyStore
            KeyStore b1 = KeyStore.getInstance("pkcs12");
            b1.load(null, null);
            b1.setKeyEntry(alias, aPrivate, keyPassword, chain);

            String extPath="mis-dspreadServer";
            extPath = CaUtils.initPath(extPath);
            String file=extPath + File.separator + alias + ".p12";
            CaUtils.exportKeyStore(file,b1,password.toCharArray());

            file=extPath + File.separator + alias + ".cer";
            FileOutputStream outStream = CaUtils.getOutStream(file);
            outStream.write(x509Cert.getEncoded());
            outStream.close();


//            KeyStore b1 = CaUtils.generateKeyStore(alias, "123456", subject,subject);

//            Certificate certificate = b1.getCertificate(alias);
//            if(certificate!=null){
//                X509CertImpl b1Cer = new X509CertImpl(certificate.getEncoded());
//                X509CertInfo b1CerInfo = (X509CertInfo) b1Cer.get(X509CertImpl.NAME +
//                        "." + X509CertImpl.INFO);
//
//                X509CertInfo x509CertInfo = new X509CertInfo();
//                x509CertInfo.set(X509CertInfo.VERSION, new CertificateVersion(2));
//                x509CertInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber((new Random()).nextInt() & 2147483647));
//                AlgorithmId algorithmID = AlgorithmId.get("SHA1WithRSA");
//                x509CertInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmID));
//                //颁发给
//                x509CertInfo.set(X509CertInfo.SUBJECT, subject);
//                x509CertInfo.set(X509CertInfo.KEY,b1CerInfo.get(X509CertInfo.KEY) );
//                x509CertInfo.set(X509CertInfo.VALIDITY, b1CerInfo.get(X509CertInfo.VALIDITY));
//                //颁发者
//
////                b1Cer.set(X509CertImpl.,rootCer.get(X509CertInfo.ISSUER));
//                x509CertInfo.set(X509CertInfo.ISSUER,rooCerInfo.get(X509CertInfo.ISSUER));
//
//
//
//
//                List<PolicyInformation> list=new ArrayList<>();
//                PolicyInformation policyInformation = new PolicyInformation(new CertificatePolicyId(new ObjectIdentifier("2.5.29.32.0")), new HashSet<>());
//                list.add(policyInformation);
//                CertificatePoliciesExtension certificatePoliciesExtension=new CertificatePoliciesExtension(list);
//
//                x509CertInfo.set(X509CertInfo.EXTENSIONS+"."+CertificatePoliciesExtension.NAME,certificatePoliciesExtension);
//                BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(true,0);
//
//                x509CertInfo.set(X509CertInfo.EXTENSIONS+"."+BasicConstraintsExtension.NAME,basicConstraintsExtension);
//                KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
//                keyUsageExtension.set(KeyUsageExtension.CRL_SIGN,true);
//                keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN,true);
//
//                x509CertInfo.set(X509CertInfo.EXTENSIONS+"."+KeyUsageExtension.NAME,keyUsageExtension);
//
//                Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
//                objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{2, 5, 29, 37, 0}));
//                ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);
//
//                x509CertInfo.set(X509CertInfo.EXTENSIONS+"."+ExtendedKeyUsageExtension.NAME,extendedKeyUsageExtension);
//
//                X509CertImpl x509Cert = new X509CertImpl(x509CertInfo);
//                x509Cert.sign(privateKey,"SHA1WithRSA");
//                b1.setCertificateEntry("root-b1",x509Cert);
//
//                String extPath="mis-b1";
//                extPath = CaUtils.initPath(extPath);
//                String file=extPath + File.separator + "root-b1" + ".cer";
//                FileOutputStream outStream = CaUtils.getOutStream(file);
//                outStream.write(x509Cert.getEncoded());
//                outStream.close();
//            }
//
//
//            String extPath="mis-b1";
//            extPath = CaUtils.initPath(extPath);
//            String file=extPath + File.separator + alias + ".p12";
//            CaUtils.exportKeyStore(file,b1,password.toCharArray());
//            try{
//                CaUtils.exportKeyStore(file,b1,password.toCharArray());
//            }catch(Exception exception){
//                exception.printStackTrace();
//            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    @Test
    public void CaUtilsTest3(){
        final String commonName = "www.c1.com";
        final String organizationalUnit = "www.c1.com";
        final String organization = "www.c1.com";
        final String city = "beijing";
        final String state = "beijing";
        final String country = "beijing";
        // 3 years
        try {
            String alias="c1";
            String password="123456";

            FileInputStream in = new FileInputStream(CaUtils.PATH+"\\mis\\b1"+File.separator+"b1.p12");
            KeyStore ks = KeyStore.getInstance("jks");
            ks.load(in, password.toCharArray());
            java.security.cert.Certificate c1 = ks.getCertificate("b1");
            X509CertImpl rootCer = new X509CertImpl(c1.getEncoded());
            X509CertInfo rooCerInfo = (X509CertInfo) rootCer.get(X509CertImpl.NAME +
                    "." + X509CertImpl.INFO);
            PrivateKey privateKey = (PrivateKey) ks.getKey("b1", password.toCharArray());

            //b1      -----
            KeyPairGenerator keyPairGenerator= null;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey aPrivate = keyPair.getPrivate();
            PublicKey aPublic = keyPair.getPublic();
            X500Name subject = new X500Name(commonName, organizationalUnit, organization, city, state, country);

            //设置cer内容
            X509CertImpl x509Cert = CaUtils.createCer(subject, 365, aPublic,(X500Name) rooCerInfo.get(X509CertInfo.SUBJECT));

            KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
            keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE,true);
            keyUsageExtension.set(KeyUsageExtension.KEY_ENCIPHERMENT,true);

            x509Cert.set(KeyUsageExtension.IDENT,keyUsageExtension);

            Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1}));
            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2}));
            ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);

            x509Cert.set(ExtendedKeyUsageExtension.IDENT,extendedKeyUsageExtension);

            GeneralNameInterface dnsName = new DNSName("www.c1.com");
            GeneralName generalName=new GeneralName(dnsName);
            GeneralNames generalNames = new GeneralNames().add(generalName);
            SubjectAlternativeNameExtension subjectAlternativeNameExtension = new SubjectAlternativeNameExtension(generalNames);
            x509Cert.set(SubjectAlternativeNameExtension.IDENT,subjectAlternativeNameExtension);

            GeneralName crlName =new GeneralName(new URIName("http://www.c1.com:8082/a.crl"));
            GeneralNames generalNames2 = new GeneralNames().add(crlName);
            DistributionPoint distributionPoint = new DistributionPoint(generalNames2, null, null);
            List<DistributionPoint> a=new ArrayList<>();
            a.add(distributionPoint);
            CRLDistributionPointsExtension crlDistributionPointsExtension = new CRLDistributionPointsExtension(a);
            x509Cert.set(CRLDistributionPointsExtension.IDENT,crlDistributionPointsExtension);

            x509Cert.sign(privateKey, "SHA256WithRSA");

            final char[] keyPassword = password.toCharArray();
            X509Certificate[] chain = new X509Certificate[2];
            chain[0] =x509Cert;
            chain[1]=rootCer;
            //加载KeyStore
            KeyStore b1 = KeyStore.getInstance("pkcs12");
            b1.load(null, null);
            b1.setKeyEntry(alias, aPrivate, keyPassword, chain);

            String extPath="cli-c1";
            extPath = CaUtils.initPath(extPath);
            String file=extPath + File.separator + alias + ".p12";
            CaUtils.exportKeyStore(file,b1,password.toCharArray());

            Certificate certificate = b1.getCertificate(alias);

            file=extPath + File.separator + "b1-c1" + ".cer";
            FileOutputStream outStream = CaUtils.getOutStream(file);
            outStream.write(certificate.getEncoded());
            outStream.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Test
    public void test1() {
        try {
            X509CertInfo cinfo2=new X509CertInfo();
            FileInputStream in = new FileInputStream("");

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(in, new char[]{'a','b'});
            java.security.cert.Certificate c1 = ks.getCertificate("alias");
//        (2)获得CA的私钥：
            PrivateKey caprk = (PrivateKey) ks.getKey("alias", new char[]{'a','b'});
//        (3)从CA的证书中提取签发者信息：
            byte[] encod1 = c1.getEncoded();
            X509CertImpl shopcimp1 = new X509CertImpl(encod1);
            X509CertInfo shopcinfo1 = (X509CertInfo) shopcimp1.get(X509CertImpl.NAME +
                    "." + X509CertImpl.INFO);
            X500Name issuer = (X500Name) shopcinfo1.get(X509CertInfo.SUBJECT +
                    "." + CertificateIssuerName.DN_NAME);
            CertificatePoliciesExtension certificatePoliciesExtension = shopcimp1.getCertificatePoliciesExtension();

//        (4)获取待签发的证书相关信息，与（3）类似；
//        (5)设置新证书的有效期、序列号、签发者和签名算法：
//设置新证书有效期为1年
            Date begindate = new Date();
            Date enddate = new Date(begindate.getTime() + 3000 * 24 * 360 * 60 * 1000L);
            CertificateValidity cv = new CertificateValidity(begindate, enddate);
            cinfo2.set(X509CertInfo.VALIDITY, cv);
//设置新证书序列号
            int sn = (int) (begindate.getTime() / 1000);
            CertificateSerialNumber csn = new CertificateSerialNumber(sn);
            cinfo2.set(X509CertInfo.SERIAL_NUMBER, csn);
//设置新证书签发者
            cinfo2.set(X509CertInfo.ISSUER + "." +
                    CertificateIssuerName.DN_NAME, issuer);
//设置新证书算法
            AlgorithmId algorithm =
                    new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
            cinfo2.set(CertificateAlgorithmId.NAME +
                    "." + CertificateAlgorithmId.ALGORITHM, algorithm);
//        (6)创建证书并签发：
// 创建证书
            X509CertImpl newcert = new X509CertImpl();
// 签名
            newcert.sign(caprk, "MD5WithRSA");
        } catch (Exception exception) {
            exception.printStackTrace();
        }


    }

    @Test
    public void test2(){
        try {
            X509CertInfo cinfo2=new X509CertInfo();

            FileInputStream in = new FileInputStream("D:\\ssl_k\\root\\server1.p12");
            KeyStore ks = KeyStore.getInstance("jks");
            ks.load(in, "123456".toCharArray());
            java.security.cert.Certificate c1 = ks.getCertificate("server1");
//        (2)获得CA的私钥：
            PrivateKey caprk = (PrivateKey) ks.getKey("server1", "123456".toCharArray());
//        (3)从CA的证书中提取签发者信息：
            byte[] encod1 = c1.getEncoded();
            X509CertImpl shopcimp1 = new X509CertImpl(encod1);

            X509CertInfo shopcinfo1 = (X509CertInfo) shopcimp1.get(X509CertImpl.NAME +
                    "." + X509CertImpl.INFO);
            X500Name issuer = (X500Name) shopcinfo1.get(X509CertInfo.SUBJECT +
                    "." + CertificateIssuerName.DN_NAME);
            List<PolicyInformation> list=new ArrayList<>();
            PolicyInformation policyInformation = new PolicyInformation(new CertificatePolicyId(new ObjectIdentifier("2.5.29.32.0")), new HashSet<>());
            list.add(policyInformation);
            CertificatePoliciesExtension certificatePoliciesExtension=new CertificatePoliciesExtension(list);
            byte[] extensionValue = certificatePoliciesExtension.getExtensionValue();
            for (int i = 0; i < extensionValue.length; i++) {
                System.out.print(Integer.toHexString((extensionValue[i] & 0xFF) + 0x100).substring(1));
            }
            shopcimp1.set(CertificatePoliciesExtension.NAME,certificatePoliciesExtension);
//        (4)获取待签发的证书相关信息，与（3）类似；
//        (5)设置新证书的有效期、序列号、签发者和签名算法：
//设置新证书有效期为1年
            Date begindate = new Date();
            Date enddate = new Date(begindate.getTime() + 3000 * 24 * 360 * 60 * 1000L);
            CertificateValidity cv = new CertificateValidity(begindate, enddate);
            cinfo2.set(X509CertInfo.VALIDITY, cv);
//设置新证书序列号
            int sn = (int) (begindate.getTime() / 1000);
            CertificateSerialNumber csn = new CertificateSerialNumber(sn);
            cinfo2.set(X509CertInfo.SERIAL_NUMBER, csn);
//设置新证书签发者
            cinfo2.set(X509CertInfo.ISSUER + "." +
                    CertificateIssuerName.DN_NAME, issuer);
//设置新证书算法
            AlgorithmId algorithm =
                    new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
            cinfo2.set(CertificateAlgorithmId.NAME +
                    "." + CertificateAlgorithmId.ALGORITHM, algorithm);
//        (6)创建证书并签发：
// 创建证书
            X509CertImpl newcert = new X509CertImpl(cinfo2);
// 签名
            newcert.sign(caprk, "MD5WithRSA");
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }


    @Test
    public void test4(){
//        tr-34 crl
//        X509Certificate
        // Builder
        try{

            KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey aPrivate = keyPair.getPrivate();
            PublicKey aPublic = keyPair.getPublic();



            CertAndKeyGen keypair2 = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            KeyStore ks = KeyStore.getInstance("pkcs12");
//            char[] password = "123456".toCharArray();
            ks.load(null, null);
            final String commonName = "www.ctbri.com";
            final String organizationalUnit = "IT";
            final String organization = "test";
            final String city = "beijing";
            final String state = "beijing";
            final String country = "beijing";
            final long validity = 1096; // 3 years
            final String alias = "tt";
            final char[] keyPassword = "123456".toCharArray();
            X500Name var1 = new X500Name(commonName, organizationalUnit, organization, city, state, country);

            Date var2 = new Date();
            long var3 = (long) validity * 24 * 60 * 60;
            X509Certificate[] chain = new X509Certificate[1];
            Date var7 = var2;
            var7.setTime(var2.getTime() + var3 * 1000L);
            CertificateValidity var8 = new CertificateValidity(var2, var7);
            X509CertInfo var9 = new X509CertInfo();
            var9.set("version", new CertificateVersion(2));
            var9.set("serialNumber", new CertificateSerialNumber((new Random()).nextInt() & 2147483647));
            AlgorithmId var10 = AlgorithmId.get("SHA1WithRSA");
            var9.set("algorithmID", new CertificateAlgorithmId(var10));
            var9.set("subject", var1);
            var9.set("key", new CertificateX509Key(aPublic));
            var9.set("validity", var8);
            var9.set("issuer", var1);


            X509CertImpl var6 = new X509CertImpl(var9);
            var6.sign(aPrivate, "SHA1WithRSA");
            chain[0] =var6;
            ks.setKeyEntry(alias, aPrivate, keyPassword, chain);

            FileOutputStream fop = new FileOutputStream(new File("D:\\ssl_k\\test\\tt.p12"));
            ks.store(fop, keyPassword);

            fop.close();
        }catch(Exception exception){
            exception.printStackTrace();
        }

    }

    @Test
    public void createCsr(){
        try {
            KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey aPrivate = keyPair.getPrivate();
            PublicKey aPublic = keyPair.getPublic();

//            KeyFactory rsa = KeyFactory.getInstance("EC");
//            RSAPublicKeySpec priv = rsa.getKeySpec(aPublic, RSAPublicKeySpec.class);
////            PublicKey publicKey = kf.generatePublic(publicKeySpec);
////            System.out.println(publicKey.toString());
////            byte[] encode = Base64Utils.encode(publicKey.getEncoded());
//            String adas = priv.getModulus().toString(16).toUpperCase();
//            System.out.println(adas);


            String sigAlg = "SHA256withRSA";
            PKCS10 pkcs10 = new PKCS10(aPublic);
            Signature signature = Signature.getInstance(sigAlg);
            signature.initSign(aPrivate);
            // common, orgUnit, org, locality, state, country
            final String commonName = "www.b1.com";
            final String organizationalUnit = "www.b1.com";
            final String organization = "www.b1.com";
            final String city = "beijing";
            final String state = "beijing";
            final String country = "beijing";
            X500Name subject = new X500Name(commonName, organizationalUnit, organization, city, state, country);
            pkcs10.encodeAndSign(subject,signature);
            ByteArrayOutputStream bs = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(bs);
            pkcs10.print(ps);
            byte[] c = bs.toByteArray();
            try {
                if (ps != null)
                    ps.close();
                if (bs != null)
                    bs.close();
            } catch (Throwable th) {
            }
            String s = new String(c);
            System.out.println(s);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    @Test
    public void csrRead(){
        try {
            String fileName="D:\\ssl_k\\root\\server1.csr";
            File file = new File(fileName);
            FileInputStream in = new FileInputStream(file);
            byte[] bytes=new byte[(int)file.length()];
            in.read(bytes);
            String s=new String(bytes);
//            System.out.println(s);
            String sb = s.replaceAll("\n","")
                    .replaceAll("\r","")
                    .replaceAll("-----[A-Z ]*-----","")
                    ;
            PKCS10 pkcs10 = new PKCS10(Base64.getDecoder().decode(sb));//解析成P10对象

//获取P10中定义的证书主题
            X500Name attr = pkcs10.getSubjectName();
//获取算法
            String alg = pkcs10.getSigAlg();
//获取P10中的公钥，这里获取的是一个公钥结构体，不是一个单纯的公钥(PS：我们C开发说的，需要用C去解析成单纯的公钥，API没有提供方法)

            PublicKey publicKey = pkcs10.getSubjectPublicKeyInfo();
            System.out.println(publicKey);

            KeyFactory rsa = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec priv = rsa.getKeySpec(publicKey, RSAPublicKeySpec.class);
//            PublicKey publicKey = kf.generatePublic(publicKeySpec);
//            System.out.println(publicKey.toString());
//            byte[] encode = Base64Utils.encode(publicKey.getEncoded());
            String adas = priv.getModulus().toString(16).toUpperCase();
            System.out.println(adas);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    @Test
    public void CrlTest(){
        try{
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            //生成秘钥
            KeyPairGenerator keyPairGenerator= null;
            try {
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey aPrivate = keyPair.getPrivate();
            PublicKey aPublic = keyPair.getPublic();

            final String commonName = "www.a1.com";
            final String organizationalUnit = "CAxx认证中心";
            final String organization = "CAxx认证中心";
            final String city = "beijing";
            final String state = "beijing";
            final String country = "beijing";
            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            nameBuilder.addRDN(BCStyle.CN, commonName);
            nameBuilder.addRDN(BCStyle.O, organization);
            nameBuilder.addRDN(BCStyle.OU,organizationalUnit);
            nameBuilder.addRDN(BCStyle.C, city);
            nameBuilder.addRDN(BCStyle.ST, city);
            nameBuilder.addRDN(BCStyle.L, city);
            org.bouncycastle.asn1.x500.X500Name x500Name = nameBuilder.build();
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                    x500Name,
                    new Date()
            );
            crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 86400 * 1000)); // 1 天有效期

            crlBuilder.addCRLEntry(BigInteger.valueOf(111L)/*被撤销证书序列号*/, new Date() /*被撤销时间*/, 1 /*被撤销原因*/);

            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
            contentSignerBuilder.setProvider("BC");
            X509CRLHolder crlHolder = crlBuilder.build(contentSignerBuilder.build(aPrivate));
            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            converter.setProvider("BC");
            X509CRL crl = converter.getCRL(crlHolder);

            FileOutputStream outStream = CaUtils.getOutStream("D:\\ssl_k\\java\\crl\\a.crl");
            outStream.write(crl.getEncoded());
            outStream.close();

        }catch(Exception exception){
            exception.printStackTrace();
        }

    }

    @Test
    public void cerRead(){
        try {
            String fileName="D:\\ssl_k\\java\\cli\\c1\\b1-c1.cer";
            File file = new File(fileName);
            FileInputStream in = new FileInputStream(file);
            byte[] bytes=new byte[(int)file.length()];
            in.read(bytes);
            X509CertImpl x509Cert = new X509CertImpl(bytes);

            X500Name x500Name = (X500Name) x509Cert.get(X509CertImpl.ISSUER_DN);
//            x509Cert.verify();
            System.out.println(x500Name);


            String fileName2="D:\\ssl_k\\java\\mis\\b1\\root-b1.cer";
            File file2 = new File(fileName2);
            FileInputStream in2 = new FileInputStream(file2);
            byte[] bytes2=new byte[(int)file2.length()];
            in2.read(bytes2);
            X509CertImpl x509Cert2 = new X509CertImpl(bytes2);
            PublicKey publicKey = x509Cert2.getPublicKey();
            x509Cert.verify(publicKey);

        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    @Test
    public void cerRead2(){
        try {
            String fileName="D:\\ssl_k\\root\\root.cer";
            File file = new File(fileName);
            FileInputStream in = new FileInputStream(file);
            byte[] bytes=new byte[(int)file.length()];
            in.read(bytes);
            String s = new String(bytes);
            String sb = s.replaceAll("\n", "")
                    .replaceAll("\r", "")
                    .replaceAll("-----[A-Z ]*-----", "");
            byte[] bytes1 = sb.getBytes();
            byte[] decode = Base64.getDecoder().decode(bytes1);
            X509CertImpl x509Cert = new X509CertImpl(decode);

            X500Name x500Name = (X500Name) x509Cert.get(X509CertImpl.ISSUER_DN);
//            x509Cert.verify();
            System.out.println(x500Name);



        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }
}
