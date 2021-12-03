package com.dspread.cara.utils;

import cn.hutool.captcha.generator.RandomGenerator;
import com.dspread.cara.entity.pojo.KeyouResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509CertInfo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Signature;
import java.util.Base64;


/**
 * 科友加密机工具类
 * @author cq
 */
@Slf4j
@Component
public class KeyouUtils {

    public static String host;
    @Value("${ca.config.host}")
    public void setHost(String host) {
        KeyouUtils.host = host;
    }
    public static int port;
    @Value("${ca.config.port}")
    public void setHost(int port) {
        KeyouUtils.port = port;
    }
    public static String rootId="0001";

    private static Socket socket;
    public static synchronized Socket getInstance() throws IOException {
        if (null == socket) {
            socket = new Socket(host, port);
        }
        return socket;
    }


    public static String lengthToString(int i){
        if(i>9999){
            throw new RuntimeException("长度超过四位");
        }
        // 0 代表前面补充0
        // 4 代表长度为4
        // d 代表参数为正数型
        String str = String.format("%04d", i);
        return str;
    }
    public static String numberToString(int i){
        if(i>1024){
            throw new RuntimeException("不可以超过1024");
        }
        // 0 代表前面补充0
        // 4 代表长度为4
        // d 代表参数为正数型
        String str = String.format("%04d", i);
        return str;
    }
    public static String numberToKey(int i){
        if(i>999){
            throw new RuntimeException("长度超过三位");
        }
        // 0 代表前面补充0
        // 4 代表长度为4
        // d 代表参数为正数型
        String str = String.format("%03d", i);
        return "K"+str;
    }
    public static KeyouResult dealResponse(byte[] response, boolean hasLength, String headString){
        final byte[] head = new byte[8];
        final byte[] status = new byte[2];
        final byte[] error = new byte[2];

        System.arraycopy(response,0,head,0,head.length);
        System.arraycopy(response,8,status,0,status.length);
        System.arraycopy(response,10,error,0,error.length);

        String headStr = new String(head);
        String statusStr = new String(status);
        String errorStr = new String(error);
        log.debug("响应头:{}", headStr);
        log.debug("状态:{}", statusStr);
        log.debug("异常:{}", errorStr);

        if(!headString.equals(headStr)){
            throw new RuntimeException("加密接接口数据被篡改");
        }
        KeyouResult keyouResult=new KeyouResult();
        keyouResult.setHead(headStr);
        keyouResult.setStatus(statusStr);
        keyouResult.setError(errorStr);
        if(!"00".equals(errorStr)){
            keyouResult.setSuccess(false);
            return keyouResult;
        }
        if(hasLength){
            final byte[] lengthBytes = new byte[4];
            System.arraycopy(response,12,lengthBytes,0,lengthBytes.length);
            String length = new String(lengthBytes);
            int size =Integer.parseInt(length);
            final byte[] data = new byte[size];
            System.arraycopy(response,16,data,0,size);
            log.debug("长度:{}",length);
            log.debug("结果:{}", Base64.getEncoder().encodeToString(data));

            keyouResult.setSuccess(true);
            keyouResult.setLength(size);
            keyouResult.setData(data);
        }else{
            int size =response.length-12;
            final byte[] data = new byte[size];
            System.arraycopy(response,12,data,0,size);
            log.debug("结果:{}",Base64.getEncoder().encodeToString(data));
            keyouResult.setSuccess(true);
            keyouResult.setLength(size);
            keyouResult.setData(data);
        }
        return  keyouResult;
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
        int readSize=0;
        while (readSize < size) {
            readSize += reader.read(buffer, readSize, size - readSize);
        }

        if (readSize != size) {
            throw new IOException("Can not read all response");
        }
        return buffer;
    }

    public static String signByRoot (X509CertInfo certInfo ) throws Exception {
        return signByKey(certInfo,rootId);
    }
    public static String signByKey (X509CertInfo certInfo ,String keyIndex) throws Exception {
        // 自定义纯数字的验证码（随机4位数字，可重复）
        RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
        String headString = randomGenerator.generate();
        Socket socket = getInstance();
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();

        byte[] param= certInfo.getEncodedInfo();


        stream.write(headString.getBytes());
        stream.write("EW".getBytes());
        stream.write("06".getBytes());
        stream.write("01".getBytes());
        stream.write("01".getBytes());
        stream.write(lengthToString(param.length).getBytes());
        stream.write(param);
        stream.write(";".getBytes());
        stream.write("K".getBytes());
        stream.write(keyIndex.getBytes());
        byte[] message = stream.toByteArray();
        byte[] response = call(socket, message);
        byte[] data1 = dealResponse(response, true, headString).getData();

        Signature sha256WithRSA = Signature.getInstance("SHA256WithRSA");
        AlgorithmId algorithmId  = AlgorithmId.get(sha256WithRSA.getAlgorithm());
        DerOutputStream var5 = new DerOutputStream();
        DerOutputStream var6 = new DerOutputStream();
        var6.write(param);
        algorithmId.encode(var6);
        var6.putBitString(data1);
        var5.write((byte)48, var6);
        byte[] cer = var5.toByteArray();
        String psB64Certificate = Base64.getEncoder().encodeToString(cer);
        psB64Certificate= CaUtils.splitString(psB64Certificate,64);

        psB64Certificate="-----BEGIN CERTIFICATE-----\n"+psB64Certificate+"\n-----END CERTIFICATE-----";

        return psB64Certificate;
    }
    public static byte[] signByEcc (byte[] param ,String keyIndex) throws Exception {
        // 自定义纯数字的验证码（随机4位数字，可重复）
        RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
        String headString = randomGenerator.generate();
        Socket socket = getInstance();
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();


//        stream.write(headString.getBytes());
//        stream.write("TO".getBytes());
//        stream.write("3".getBytes());
//        stream.write(lengthToString(param.length).getBytes());
//        stream.write(param);
//
//        byte[] shaData = stream.toByteArray();
//        final byte[] shaResponse = call(socket, shaData );
//
//        byte[] data = dealResponse(shaResponse,false,headString).getData();

//        AlgorithmIdentifier sha256Aid = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
//        DigestInfo di = new DigestInfo(sha256Aid, data);
//        byte[] encodedDigestInfo = di.toASN1Primitive().getEncoded();
        headString = randomGenerator.generate();
        stream.reset();
        stream.write(headString.getBytes());
        stream.write("L7".getBytes());
        stream.write("2".getBytes());
        stream.write(keyIndex.getBytes());
        stream.write(lengthToString(param.length).getBytes());
        stream.write(param);

        byte[] signData = stream.toByteArray();

        final byte[] sigResponse = call(socket, signData );

        byte[] data = dealResponse(sigResponse,true,headString).getData();

        return data;
    }
    public static byte[] signByEcc2 (byte[] param ,String keyIndex) throws Exception {
        // 自定义纯数字的验证码（随机4位数字，可重复）
        RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
        String headString = randomGenerator.generate();
        Socket socket = getInstance();
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();

        stream.write(headString.getBytes());
        stream.write("L7".getBytes());
        stream.write("1".getBytes());
        stream.write(keyIndex.getBytes());
        stream.write(lengthToString(param.length).getBytes());
        stream.write(param);

        byte[] message = stream.toByteArray();
        byte[] response = call(socket, message);
        byte[] data = dealResponse(response, true, headString).getData();

        return data;
    }
}
