package com.dspread.cara;

import cn.hutool.captcha.generator.RandomGenerator;
import com.dspread.cara.entity.pojo.KeyouResult;
import com.dspread.cara.utils.CaUtils;
import com.dspread.cara.utils.KeyouUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attributes;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

@Slf4j
public class SocketTest {

    private static final String host = "172.16.10.220";
    private static final int port = 1818;

    private static Socket socket;

    public static synchronized Socket getInstance() throws IOException {
        if (null == socket) {
            socket = new Socket(host, port);
        }
        return socket;
    }


    @Test
    public void jiamiji1() {
        try {
            Socket s = new Socket("172.16.10.220", 1818);//进入端口，前面是服务器的Ip，自己电脑一般是127.0.0.1,后面的是端口，与服务器对应
            s.setKeepAlive(true);
            s.setSoTimeout(2000);

            OutputStream outputStream = s.getOutputStream();//IO流发送
            StringBuffer sb = new StringBuffer();
            sb.append("12345678NC");
            byte[] bytes1 = sb.toString().getBytes();
            int length = bytes1.length;
            byte b = (byte) (length >>> 8 & 0xFF);
            byte b1 = (byte) (length & 0xFF);
            byte[] data = new byte[length + 2];
            data[0] = b;
            data[1] = b1;
            System.arraycopy(bytes1, 0, data, 2, 10);

            outputStream.write(data);
            outputStream.flush();
            InputStream inputStream = s.getInputStream();//读取数据
            int size;
            final byte[] sizeLen = new byte[2];
            size = inputStream.read(sizeLen);
            if (size != 2) {
                throw new IOException("The response head size error");
            }
            size = new BigInteger(1, sizeLen).intValue();
            final byte[] buffer = new byte[size];
            final int readSize = inputStream.read(buffer);
            if (readSize != size) {
                throw new IOException("Can not read all response");
            }
            String msg = Arrays.toString(buffer);
            log.debug(msg);
            log.debug(new String(buffer));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    /**
     * 一个简单的HTTP客户端，发送HTTP请求，模拟浏览器 * 可打印服务器发送过来的HTTP消息
     */
    public static byte[] call(Socket socket, byte[] message) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        int size = message.length;
        stream.write((byte) (size >>> 8 & 0xFF));
        stream.write((byte) (size & 0xFF));
        stream.write(message);
        final OutputStream writer = socket.getOutputStream();
        writer.write(stream.toByteArray());
        writer.flush();

        final InputStream reader = socket.getInputStream();
        final byte[] sizeLen = new byte[2];
        size = reader.read(sizeLen);
        if (size != 2) {
            throw new IOException("The response head size error");
        }
        size = new BigInteger(1, sizeLen).intValue();
        log.debug("返回长度:{}", size);
        final byte[] buffer = new byte[size];
        int readSize = 0;
        while (readSize < size) {
            readSize += reader.read(buffer, readSize, size - readSize);
        }

        if (readSize != size) {
            throw new IOException("Can not read all response");
        }
        return buffer;
    }

    @Test
    public void generateRoot() {
        try {
            Socket socket = getInstance();
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write("12345678".getBytes());
            stream.write("34".getBytes());
            stream.write("4096".getBytes());
            stream.write("K".getBytes());
            stream.write("0001".getBytes());
            byte[] message = stream.toByteArray();
            final byte[] response = call(socket, message);
            final byte[] head = new byte[8];
            final byte[] status = new byte[2];
            final byte[] error = new byte[2];
            final byte[] lengthBytes = new byte[4];
            System.arraycopy(response, 0, head, 0, 8);
            System.arraycopy(response, 8, status, 0, 2);
            System.arraycopy(response, 10, error, 0, 2);
            System.arraycopy(response, 12, lengthBytes, 0, 4);

            String length = new String(lengthBytes);
            int keySize = Integer.parseInt(length);
            final byte[] key = new byte[keySize];
            System.arraycopy(response, 16, key, 0, keySize);
            final byte[] pub = new byte[response.length - 16 - keySize];
            System.arraycopy(response, 16 + keySize, pub, 0, pub.length);


            log.debug("响应头:{}", new String(head));
            log.debug("状态:{}", new String(status));
            log.debug("异常:{}", new String(error));
            log.debug("秘钥长度:{}", length);
            log.debug("秘钥:{}", Base64.getEncoder().encodeToString(key));
            log.debug("公钥:{}", Base64.getEncoder().encodeToString(pub));
//            log.debug(new String(response));
            System.out.println(Arrays.toString(response));
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    @Test
    public void getRootCer() {
        try {
            Socket socket = getInstance();
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();

            // 自定义纯数字的验证码（随机4位数字，可重复）
            RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
            String headString = randomGenerator.generate();

            stream.write(headString.getBytes());
            stream.write("TW".getBytes());
            stream.write("0".getBytes());
            stream.write("K001".getBytes());
            stream.write("01".getBytes());
            byte[] message = stream.toByteArray();
            final byte[] response = call(socket, message);

            KeyouResult keyouResult = dealResponse(response, true, headString);
            boolean success = keyouResult.isSuccess();
            if (success) {
                byte[] data = keyouResult.getData();
                log.debug("公钥:{}", Base64.getEncoder().encodeToString(data));

                // 取得公钥  for PKCS#1
                RSAPublicKeyStructure asn1pub = new RSAPublicKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(data));
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(asn1pub.getModulus(), asn1pub.getPublicExponent());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey aPublic = keyFactory.generatePublic(rsaPublicKeySpec);

                final String commonNameRoot = "www.dspread.com";
                final String organizationalUnitRoot = "CARA认证中心";
                final String organizationRoot = "CARA认证中心";
                final String cityRoot = "beijing";
                final String stateRoot = "beijing";
                final String countryRoot = "CN";
                X500Name issuer = new X500Name(commonNameRoot, organizationalUnitRoot, organizationRoot, cityRoot, stateRoot, countryRoot);
                //设置cer内容
                X509CertImpl x509Cert = CaUtils.createCer(issuer, 365 * 10, aPublic, issuer);
                X509CertInfo x509CertInfo = (X509CertInfo) x509Cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

                String s = signByRoot(x509CertInfo);

//                s = s.replaceAll("\n", "")
////                    .replaceAll("%2", "")
//                        .replaceAll("\r", "")
//                        .replaceAll(" ", "")
//                        .replaceAll("-----[A-Z ]*-----", "");
//                X509CertImpl x509Cert1 = new X509CertImpl(Base64.getDecoder().decode(s));
//                PublicKey publicKey = x509Cert1.getPublicKey();
////                x509Cert1.verify(publicKey);
                log.debug("\n" + s);
            } else {
                String error = keyouResult.getError();
                if ("12".equals(error)) {
                    throw new RuntimeException("根秘钥未初始化");
                }
            }


        } catch (CertificateException certificateException) {
            log.error(certificateException.getLocalizedMessage());
            certificateException.printStackTrace();
        } catch (Exception exception) {
            log.error(exception.getMessage());
            exception.printStackTrace();
        }

    }


    @Test
    public void getServerCer() {
        // 自定义纯数字的验证码（随机4位数字，可重复）
        RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
        String headString = randomGenerator.generate();
        try {
            final Socket socket = getInstance();
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(headString.getBytes());
            stream.write("34".getBytes());
            stream.write("4096".getBytes());
            stream.write("K".getBytes());
            stream.write("0002".getBytes());
            byte[] message = stream.toByteArray();
            final byte[] response = call(socket, message);

            byte[] data = dealResponse(response, false, headString).getData();
            final byte[] lengthBytes = new byte[4];
            System.arraycopy(data, 0, lengthBytes, 0, lengthBytes.length);
            String length = new String(lengthBytes);
            int keySize = Integer.parseInt(length);
            final byte[] key = new byte[keySize];
            System.arraycopy(data, 4, key, 0, keySize);
            final byte[] pub = new byte[response.length - 16 - keySize];
            System.arraycopy(data, 4 + keySize, pub, 0, pub.length);


            log.debug("秘钥长度:{}", length);
            log.debug("秘钥:{}", Base64.getEncoder().encodeToString(key));
            log.debug("公钥:{}", Base64.getEncoder().encodeToString(pub));

            // 取得私钥  for PKCS#1
            RSAPublicKeyStructure asn1pub = new RSAPublicKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(pub));
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(asn1pub.getModulus(), asn1pub.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey aPublic = keyFactory.generatePublic(rsaPublicKeySpec);

            final String commonName = "cs.dspread.net";
            final String organizationalUnit = "dspread.net";
            final String organization = "dspread.net";
            final String city = "beijing";
            final String state = "beijing";
            final String country = "CN";

            final String commonNameRoot = "www.dspread.com";
            final String organizationalUnitRoot = "CARA认证中心";
            final String organizationRoot = "CARA认证中心";
            final String cityRoot = "beijing";
            final String stateRoot = "beijing";
            final String countryRoot = "CN";
            X500Name subject = new X500Name(commonName, organizationalUnit, organization, city, state, country);
            X500Name issuer = new X500Name(commonNameRoot, organizationalUnitRoot, organizationRoot, cityRoot, stateRoot, countryRoot);
            //设置cer内容
            X509CertImpl x509Cert = CaUtils.createCer(subject, 365, aPublic, issuer);

            List<PolicyInformation> list = new ArrayList<>();
            PolicyInformation policyInformation = new PolicyInformation(new CertificatePolicyId(new ObjectIdentifier("2.5.29.32.0")), new HashSet<>());
            list.add(policyInformation);
            CertificatePoliciesExtension certificatePoliciesExtension = new CertificatePoliciesExtension(list);

            x509Cert.set(CertificatePoliciesExtension.IDENT, certificatePoliciesExtension);
            BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(true, 0);

            x509Cert.set(BasicConstraintsExtension.IDENT, basicConstraintsExtension);
            KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
            keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
            keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);

            x509Cert.set(KeyUsageExtension.IDENT, keyUsageExtension);

            Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{2, 5, 29, 37, 0}));
            ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);

            x509Cert.set(ExtendedKeyUsageExtension.IDENT, extendedKeyUsageExtension);
            X509CertInfo x509CertInfo = (X509CertInfo) x509Cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

            String s = signByRoot(x509CertInfo);

            log.debug("\n" + s);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    public static String signByRoot2(X509CertInfo certInfo) throws Exception {
        // 自定义纯数字的验证码（随机4位数字，可重复）
        RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
        String headString = randomGenerator.generate();
        Socket socket = getInstance();
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();

        byte[] param = certInfo.getEncodedInfo();

        stream.write(headString.getBytes());
        stream.write("TO".getBytes());
        stream.write("3".getBytes());
        stream.write(lengthToString(param.length).getBytes());
        stream.write(param);

        byte[] shaData = stream.toByteArray();
        final byte[] shaResponse = call(socket, shaData);

        byte[] data = dealResponse(shaResponse, false, headString).getData();
        AlgorithmIdentifier sha256Aid = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        DigestInfo di = new DigestInfo(sha256Aid, data);
        byte[] encodedDigestInfo = di.toASN1Primitive().getEncoded();
        byte[] encode = Hex.encode(encodedDigestInfo);
        log.debug(new String(encode));
        headString = randomGenerator.generate();
        stream.reset();
        stream.write(headString.getBytes());
        stream.write("37".getBytes());
        stream.write("1".getBytes());
        stream.write("01".getBytes());
        stream.write(lengthToString(encode.length).getBytes());
        stream.write(encode);

        byte[] signData = stream.toByteArray();

        final byte[] sigResponse = call(socket, signData);

        data = dealResponse(sigResponse, true, headString).getData();

        Signature sha256WithRSA = Signature.getInstance("SHA256WithRSA");
        AlgorithmId algorithmId = AlgorithmId.get(sha256WithRSA.getAlgorithm());
        DerOutputStream var5 = new DerOutputStream();
        DerOutputStream var6 = new DerOutputStream();
        var6.write(param);
        algorithmId.encode(var6);
        var6.putBitString(data);
        var5.write((byte) 48, var6);
        byte[] cer = var5.toByteArray();
        String psB64Certificate = Base64.getEncoder().encodeToString(cer);
        psB64Certificate = CaUtils.splitString(psB64Certificate, 64);

        psB64Certificate = "-----BEGIN CERTIFICATE-----\n" + psB64Certificate + "\n-----END CERTIFICATE-----";

        return psB64Certificate;
    }

    public static String signByRoot(X509CertInfo certInfo) throws Exception {
        // 自定义纯数字的验证码（随机4位数字，可重复）
        RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
        String headString = randomGenerator.generate();
        Socket socket = getInstance();
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();

        byte[] param = certInfo.getEncodedInfo();


        stream.write(headString.getBytes());
        stream.write("EW".getBytes());
        stream.write("06".getBytes());
        stream.write("01".getBytes());
        stream.write("01".getBytes());
        stream.write(lengthToString(param.length).getBytes());
        stream.write(param);
        stream.write(";".getBytes());
        stream.write("K".getBytes());
        stream.write("0001".getBytes());
        byte[] message = stream.toByteArray();
        byte[] response = call(socket, message);
        byte[] data1 = dealResponse(response, true, headString).getData();

        Signature sha256WithRSA = Signature.getInstance("SHA256WithRSA");
        AlgorithmId algorithmId = AlgorithmId.get(sha256WithRSA.getAlgorithm());
        DerOutputStream var5 = new DerOutputStream();
        DerOutputStream var6 = new DerOutputStream();
        var6.write(param);
        algorithmId.encode(var6);
        var6.putBitString(data1);
        var5.write((byte) 48, var6);
        byte[] cer = var5.toByteArray();
        String psB64Certificate = Base64.getEncoder().encodeToString(cer);
        psB64Certificate = CaUtils.splitString(psB64Certificate, 64);

        psB64Certificate = "-----BEGIN CERTIFICATE-----\n" + psB64Certificate + "\n-----END CERTIFICATE-----";

        return psB64Certificate;
    }

    @Test
    public void name() {
        final byte[] bytes = "|".getBytes();
        log.debug(Arrays.toString(bytes));
    }

    public static String lengthToString(int i) {
        if (i > 9999) {
            throw new RuntimeException("长度超过四位");
        }
        // 0 代表前面补充0
        // 4 代表长度为4
        // d 代表参数为正数型
        String str = String.format("%04d", i);
        return str;
    }

    public static String numberToString(int i) {
        if (i > 1024) {
            throw new RuntimeException("长度超过四位");
        }
        // 0 代表前面补充0
        // 4 代表长度为4
        // d 代表参数为正数型
        String str = String.format("%04d", i);
        return str;
    }

    public static KeyouResult dealResponse(byte[] response, boolean hasLength, String headString) {
        final byte[] head = new byte[8];
        final byte[] status = new byte[2];
        final byte[] error = new byte[2];

        System.arraycopy(response, 0, head, 0, head.length);
        System.arraycopy(response, 8, status, 0, status.length);
        System.arraycopy(response, 10, error, 0, error.length);

        String headStr = new String(head);
        String statusStr = new String(status);
        String errorStr = new String(error);
        log.debug("响应头:{}", headStr);
        log.debug("状态:{}", statusStr);
        log.debug("异常:{}", errorStr);

        if (!headString.equals(headStr)) {
            throw new RuntimeException("加密接接口数据被篡改");
        }
        KeyouResult keyouResult = new KeyouResult();
        keyouResult.setHead(headStr);
        keyouResult.setStatus(statusStr);
        keyouResult.setError(errorStr);
        if (!"00".equals(errorStr)) {
            keyouResult.setSuccess(false);
            return keyouResult;
        }
        if (hasLength) {
            final byte[] lengthBytes = new byte[4];
            System.arraycopy(response, 12, lengthBytes, 0, lengthBytes.length);
            String length = new String(lengthBytes);
            int size = Integer.parseInt(length);
            final byte[] data = new byte[size];
            System.arraycopy(response, 16, data, 0, size);
            log.debug("长度:{}", length);
            log.debug("结果:{}", Base64.getEncoder().encodeToString(data));

            keyouResult.setSuccess(true);
            keyouResult.setLength(size);
            keyouResult.setData(data);
        } else {
            int size = response.length - 12;
            final byte[] data = new byte[size];
            System.arraycopy(response, 12, data, 0, size);
            log.debug("结果:{}", Base64.getEncoder().encodeToString(data));
            keyouResult.setLength(size);
            keyouResult.setData(data);
        }
        return keyouResult;
    }


    @Test
    public void rsa2() {

    }

    @Test
    public void getRootCer2() {
        try {
            Socket socket = getInstance();
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();

            // 自定义纯数字的验证码（随机4位数字，可重复）
            RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
            String headString = randomGenerator.generate();

            stream.write(headString.getBytes());
            stream.write("TW".getBytes());
            stream.write("0".getBytes());
            stream.write("K001".getBytes());
            stream.write("01".getBytes());
            byte[] message = stream.toByteArray();
            byte[] response = call(socket, message);

            KeyouResult keyouResult = dealResponse(response, true, headString);
            boolean success = keyouResult.isSuccess();
            if (success) {
                byte[] data = keyouResult.getData();
                log.debug("公钥:{}", Base64.getEncoder().encodeToString(data));

                // 取得公钥  for PKCS#1
                RSAPublicKeyStructure asn1pub = new RSAPublicKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(data));
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(asn1pub.getModulus(), asn1pub.getPublicExponent());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey aPublic = keyFactory.generatePublic(rsaPublicKeySpec);

                final String commonNameRoot = "www.dspread.com";
                final String organizationalUnitRoot = "CARA认证中心";
                final String organizationRoot = "CARA认证中心";
                final String cityRoot = "beijing";
                final String stateRoot = "beijing";
                final String countryRoot = "CN";
                X500Name issuer = new X500Name(commonNameRoot, organizationalUnitRoot, organizationRoot, cityRoot, stateRoot, countryRoot);
                //设置cer内容
                X509CertImpl x509Cert = CaUtils.createCer(issuer, 365 * 10, aPublic, issuer);
                X509CertInfo x509CertInfo = (X509CertInfo) x509Cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

                byte[] encodedInfo = x509CertInfo.getEncodedInfo();
                byte[] encode = Hex.encode(encodedInfo);

                log.debug("---------------------");
                stream.reset();
                stream.write(headString.getBytes());
                stream.write("EW".getBytes());
                stream.write("06".getBytes());
                stream.write("01".getBytes());
                stream.write("01".getBytes());
                stream.write(lengthToString(encodedInfo.length).getBytes());
                stream.write(encodedInfo);
                stream.write(";".getBytes());
                stream.write("K".getBytes());
                stream.write("0001".getBytes());
                message = stream.toByteArray();
                response = call(socket, message);
                byte[] data1 = dealResponse(response, true, headString).getData();

                Signature sha256WithRSA = Signature.getInstance("SHA256WithRSA");
                AlgorithmId algorithmId = AlgorithmId.get(sha256WithRSA.getAlgorithm());
                DerOutputStream var5 = new DerOutputStream();
                DerOutputStream var6 = new DerOutputStream();
                var6.write(encodedInfo);
                algorithmId.encode(var6);
                var6.putBitString(data1);
                var5.write((byte) 48, var6);
                byte[] cer = var5.toByteArray();
                String psB64Certificate = Base64.getEncoder().encodeToString(cer);
                psB64Certificate = CaUtils.splitString(psB64Certificate, 64);

                psB64Certificate = "-----BEGIN CERTIFICATE-----\n" + psB64Certificate + "\n-----END CERTIFICATE-----";

                log.debug(psB64Certificate);
            } else {
                String error = keyouResult.getError();
                if ("12".equals(error)) {
                    throw new RuntimeException("根秘钥未初始化");
                }
            }


        } catch (CertificateException certificateException) {
            log.error(certificateException.getLocalizedMessage());
            certificateException.printStackTrace();
        } catch (Exception exception) {
            log.error(exception.getMessage());
            exception.printStackTrace();
        }

    }

    @Test
    public void getServerCer2() {
        // 自定义纯数字的验证码（随机4位数字，可重复）
        RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
        String headString = randomGenerator.generate();
        try {
            final Socket socket = getInstance();
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(headString.getBytes());
            stream.write("34".getBytes());
            stream.write("4096".getBytes());
            stream.write("K".getBytes());
            stream.write("0002".getBytes());
            byte[] message = stream.toByteArray();
            byte[] response = call(socket, message);

            byte[] data = dealResponse(response, false, headString).getData();
            final byte[] lengthBytes = new byte[4];
            System.arraycopy(data, 0, lengthBytes, 0, lengthBytes.length);
            String length = new String(lengthBytes);
            int keySize = Integer.parseInt(length);
            final byte[] key = new byte[keySize];
            System.arraycopy(data, 4, key, 0, keySize);
            final byte[] pub = new byte[response.length - 16 - keySize];
            System.arraycopy(data, 4 + keySize, pub, 0, pub.length);


            log.debug("秘钥长度:{}", length);
            log.debug("秘钥:{}", Base64.getEncoder().encodeToString(key));
            log.debug("公钥:{}", Base64.getEncoder().encodeToString(pub));

            // 取得私钥  for PKCS#1
            RSAPublicKeyStructure asn1pub = new RSAPublicKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(pub));
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(asn1pub.getModulus(), asn1pub.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey aPublic = keyFactory.generatePublic(rsaPublicKeySpec);


            Signature sha256WithRSA = Signature.getInstance("SHA256WithRSA");
            AlgorithmId algorithmId = AlgorithmId.get(sha256WithRSA.getAlgorithm());

            final String commonName = "cs.dspread.net";
            final String organizationalUnit = "dspread.net";
            final String organization = "dspread.net";
            final String city = "beijing";
            final String state = "beijing";
            final String country = "CN";
            X500Name subject = new X500Name(commonName, organizationalUnit, organization, city, state, country);

            DerOutputStream var4 = new DerOutputStream();
            var4.putInteger(BigInteger.ZERO);
            subject.encode(var4);
            var4.write(aPublic.getEncoded());
            new PKCS10Attributes().encode(var4);
            DerOutputStream var3 = new DerOutputStream();
            var3.write((byte) 48, var4);
            byte[] var5 = var3.toByteArray();
            var4 = var3;
            // 自定义纯数字的验证码（随机4位数字，可重复）
            headString = randomGenerator.generate();

            stream.reset();
            stream.write(headString.getBytes());
            stream.write("EW".getBytes());
            stream.write("06".getBytes());
            stream.write("01".getBytes());
            stream.write("01".getBytes());
            stream.write(lengthToString(var5.length).getBytes());
            stream.write(var5);
            stream.write(";".getBytes());
            stream.write("K".getBytes());
            stream.write("0002".getBytes());
            message = stream.toByteArray();
            response = call(socket, message);
            byte[] var6 = dealResponse(response, true, headString).getData();

            AlgorithmId var7 = algorithmId;

            var7.encode(var3);
            var3.putBitString(var6);
            var3 = new DerOutputStream();
            var3.write((byte) 48, var4);
            byte[] bytes = var3.toByteArray();

            PKCS10 pkcs10 = new PKCS10(bytes);


            String sigAlg = pkcs10.getSigAlg();
            X500Name subjectName = pkcs10.getSubjectName();
            PublicKey publicKey = pkcs10.getSubjectPublicKeyInfo();

            final String commonNameRoot = "www.dspread.com";
            final String organizationalUnitRoot = "CARA认证中心";
            final String organizationRoot = "CARA认证中心";
            final String cityRoot = "beijing";
            final String stateRoot = "beijing";
            final String countryRoot = "CN";

            X500Name issuer = new X500Name(commonNameRoot, organizationalUnitRoot, organizationRoot, cityRoot, stateRoot, countryRoot);

            X509CertImpl x509Cert = CaUtils.createCer(subject, 365 * 3, publicKey, issuer);

            if (!sigAlg.equalsIgnoreCase("SHA256WithRSA")) {
                log.error("加密方式错误");
                return;
            }


            List<PolicyInformation> list = new ArrayList<>();
            PolicyInformation policyInformation = new PolicyInformation(new CertificatePolicyId(new ObjectIdentifier("2.5.29.32.0")), new HashSet<>());
            list.add(policyInformation);
            CertificatePoliciesExtension certificatePoliciesExtension = new CertificatePoliciesExtension(list);

            x509Cert.set(CertificatePoliciesExtension.IDENT, certificatePoliciesExtension);
            BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(true, 0);

            x509Cert.set(BasicConstraintsExtension.IDENT, basicConstraintsExtension);
            KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
            keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
            keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);

            x509Cert.set(KeyUsageExtension.IDENT, keyUsageExtension);

            Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{2, 5, 29, 37, 0}));
            ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);

            x509Cert.set(ExtendedKeyUsageExtension.IDENT, extendedKeyUsageExtension);
            X509CertInfo x509CertInfo = (X509CertInfo) x509Cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

            String s = signByRoot(x509CertInfo);

            log.debug("\n" + s);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

    @Test
    public void eccInit() {
        try{
            socket = new Socket("172.16.10.220", 1818);
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();
            String headString = "12345678";
            stream.reset();
            stream.write(headString.getBytes());
            stream.write("L1".getBytes());
            stream.write("4".getBytes());
            stream.write(KeyouUtils.numberToString(1).getBytes());
            byte[] message = stream.toByteArray();
            byte[] response = KeyouUtils.call(socket, message);

            byte[] data = KeyouUtils.dealResponse(response, false, headString).getData();
            final byte[] lengthBytes = new byte[4];
            System.arraycopy(data, 0, lengthBytes, 0, lengthBytes.length);
            String length = new String(lengthBytes);
            int keySize = Integer.parseInt(length);
            final byte[] key = new byte[keySize];
            System.arraycopy(data, 4, key, 0, keySize);
            byte[] pub = new byte[data.length - 4 - keySize];
            System.arraycopy(data, 4 + keySize, pub, 0, pub.length);
//            pub[0]=4;


            DERBitString bitString = new DERBitString(pub);
            ASN1EncodableVector otherName = new ASN1EncodableVector();
            final String ecPublicKey  = "1.2.840.10045.2.1";
            final String secp256k1  = "1.3.132.0.10";
            otherName.add(new ASN1ObjectIdentifier(ecPublicKey));
            otherName.add(new ASN1ObjectIdentifier(secp256k1));
            DERSequence asn1Encodables = new DERSequence(otherName);
            ASN1EncodableVector otherName2 = new ASN1EncodableVector();
            otherName2.add(asn1Encodables);
            otherName2.add(bitString);
            DERSequence asn1Encodables2 = new DERSequence(otherName2);
            byte[] encoded = asn1Encodables2.getEncoded();
            System.out.println(Base64.getEncoder().encodeToString(encoded));


//            ECPublicKey ecPublicKey = new ECPublicKey();

            log.debug("秘钥长度:{}", length);
            log.debug("秘钥:{}", Base64.getEncoder().encodeToString(key));
            log.debug("公钥:{}", Base64.getEncoder().encodeToString(pub));
            log.debug("公钥:{}", Arrays.toString(pub));
        }catch(Exception exception){
            exception.printStackTrace();
        }


    }

}
