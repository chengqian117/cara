package com.dspread.cara.controller;

import cn.hutool.captcha.generator.RandomGenerator;
import com.dspread.cara.common.CaConfig;
import com.dspread.cara.config.ResultData;
import com.dspread.cara.config.ResultViewModel;
import com.dspread.cara.entity.SignDto;
import com.dspread.cara.entity.pojo.KeyouResult;
import com.dspread.cara.utils.CaUtils;
import com.dspread.cara.utils.EccUtils;
import com.dspread.cara.utils.KeyouUtils;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.*;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attributes;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.*;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Vector;

@RestController
@RequestMapping("/cara/ecc")
@Api(value = "cara Ecc在线服务",tags = "cara Ecc在线服务")
@Slf4j
@Profile(value = {"prod","test"})
public class EccCaraController {

    @Autowired
    CaConfig caConfig;

    final String country = "CN";

    @ApiOperation(value = "二级证书生成csr",httpMethod = "GET")
    @GetMapping("generateServiceCsr")
    public void generateServiceCsr( HttpServletResponse httpServletResponse){
        String me="CA证书 generateServiceCsr---------";
//        id= (id==null||id.equals(0))?1:id;
        int id=1;
        log.info(me);
        //有效年数
        try{
            Socket socket = KeyouUtils.getInstance();
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();
            // 自定义纯数字的验证码（随机4位数字，可重复）
            RandomGenerator randomGenerator = new RandomGenerator("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 8);
            String headString = randomGenerator.generate();
            stream.write(headString.getBytes());
            stream.write("L5".getBytes());
            stream.write(KeyouUtils.numberToString(id).getBytes());
            stream.write("1".getBytes());
            byte[] message = stream.toByteArray();
            byte[] response = KeyouUtils.call(socket, message);
            KeyouResult keyouResult = KeyouUtils.dealResponse(response, false, headString);

            byte[] pub ;
            boolean success = keyouResult.isSuccess();
            if (success) {
                byte[] data = keyouResult.getData();
                final byte[] lengthBytes = new byte[4];
                System.arraycopy(data, 0, lengthBytes, 0, lengthBytes.length);
                String length = new String(lengthBytes);
                int keySize = Integer.parseInt(length);
                final byte[] key = new byte[keySize];
                System.arraycopy(data, 4, key, 0, keySize);
                pub = new byte[response.length - 16 - keySize];
                System.arraycopy(data, 4 + keySize, pub, 0, pub.length);


                log.debug("s秘钥长度:{}", length);
                log.debug("s秘钥:{}", Base64.getEncoder().encodeToString(key));
            } else {
                headString = randomGenerator.generate();
                stream.reset();
                stream.write(headString.getBytes());
                stream.write("L1".getBytes());
                stream.write("1".getBytes());
                stream.write(KeyouUtils.numberToString(id).getBytes());
                message = stream.toByteArray();
                response = KeyouUtils.call(socket, message);

                byte[] data = KeyouUtils.dealResponse(response, false, headString).getData();
                final byte[] lengthBytes = new byte[4];
                System.arraycopy(data, 0, lengthBytes, 0, lengthBytes.length);
                String length = new String(lengthBytes);
                int keySize = Integer.parseInt(length);
                final byte[] key = new byte[keySize];
                System.arraycopy(data, 4, key, 0, keySize);
                pub = new byte[response.length - 16 - keySize];
                System.arraycopy(data, 4 + keySize, pub, 0, pub.length);


                log.debug("秘钥长度:{}", length);
                log.debug("秘钥:{}", Base64.getEncoder().encodeToString(key));
            }
            log.debug("公钥:{}", Base64.getEncoder().encodeToString(pub));
            log.debug("公钥:{}", Arrays.toString(pub));


            PublicKey aPublic = EccUtils.paseKey(pub);


            Signature signature = Signature.getInstance("SHA256withECDSA");
            AlgorithmId algorithmId  = AlgorithmId.get(signature.getAlgorithm());


            X500Name subject = new X500Name(caConfig.getServerSubject(),
                    caConfig.getServerSubject(), caConfig.getServerSubject(), caConfig.getCity(), caConfig.getState(), country);

            DerOutputStream var4 = new DerOutputStream();
            var4.putInteger(BigInteger.ZERO);
            subject.encode(var4);
            var4.write(aPublic.getEncoded());
            new PKCS10Attributes().encode(var4);
            DerOutputStream var3 = new DerOutputStream();
            var3.write((byte)48, var4);
            byte[] var5 = var3.toByteArray();
            var4 = var3;
            // 自定义纯数字的验证码（随机4位数字，可重复）
            headString = randomGenerator.generate();

            byte[] var6 = KeyouUtils.signByEcc(var5, KeyouUtils.numberToString(id));

            AlgorithmId var7 = algorithmId;

            var7.encode(var3);
            var3.putBitString(var6);
            var3 = new DerOutputStream();
            var3.write((byte)48, var4);
            byte[] bytes = var3.toByteArray();

            PKCS10 pkcs10 = new PKCS10(bytes);

            byte[] var2 = {13, 10};
            String csr="";
            csr+=("-----BEGIN NEW CERTIFICATE REQUEST-----\n");
            csr+=(Base64.getMimeEncoder(64, var2).encodeToString(bytes));
            csr+=("\n-----END NEW CERTIFICATE REQUEST-----");
            httpServletResponse.setCharacterEncoding("utf-8");
            httpServletResponse.setContentType("application/force-download");
            httpServletResponse.setContentType("multipart/form-data");
            httpServletResponse.setHeader("Access-Control-Expose-Headers", "Content-Disposition");
            String fileName = URLEncoder.encode(caConfig.getServerName()+".csr", "utf-8");
            // 设置文件名
            httpServletResponse.addHeader("Content-Disposition", "attachment;filename=" +fileName);
            ServletOutputStream outputStream = httpServletResponse.getOutputStream();
            outputStream.write(csr.getBytes());
            outputStream.flush();
            outputStream.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }


    @PostMapping("signByServer")
    @ApiOperation(value = "通过二级服务签字",httpMethod = "POST")
    public ResultViewModel signByServer(@RequestBody SignDto signDto) {
        String csr=signDto.getFile();

        String me = " CA证书 signByServer---------" ;
        log.info(me);

        log.debug(csr);
        if (StringUtils.isEmpty(csr) ) {
            log.error(me + csr );
            return ResultData.error();
        }
        try {
            csr = csr.replaceAll("\n", "")
                    .replaceAll("\r", "")
                    .replaceAll(" ", "")
                    .replaceAll("-----[A-Z ]*-----", "");

            PKCS10 pkcs10 = new PKCS10(Base64.getDecoder().decode(csr));//解析成P10对象
            //获取P10中定义的证书主题
            X500Name subject = pkcs10.getSubjectName();
            //获取算法
            String alg = pkcs10.getSigAlg();
            String algDefault="SHA256WithRSA";
            if(!algDefault.equalsIgnoreCase(alg)){
                return ResultData.success("加密方式只支持"+algDefault);
            }
            //获取P10中的公钥，这里获取的是一个公钥结构体，不是一个单纯的公钥(PS：我们C开发说的，需要用C去解析成单纯的公钥，API没有提供方法)
            PublicKey publicKey = pkcs10.getSubjectPublicKeyInfo();

            X500Name issuer = new X500Name(caConfig.getServerSubject(),
                    caConfig.getServerSubject(), caConfig.getServerSubject(), caConfig.getCity(), caConfig.getState(), country);

            //设置cer内容
            X509CertImpl x509Cert = CaUtils.createCer(subject, 365*3, publicKey,issuer);


            KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
            keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
            keyUsageExtension.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);

            x509Cert.set(KeyUsageExtension.IDENT, keyUsageExtension);

            Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1}));
            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2}));
            ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);

            x509Cert.set(ExtendedKeyUsageExtension.IDENT, extendedKeyUsageExtension);

            //dns
//            GeneralNameInterface dnsName = new DNSName("www.c1.com");
//            GeneralName generalName = new GeneralName(dnsName);
//            GeneralNames generalNames = new GeneralNames().add(generalName);
//            SubjectAlternativeNameExtension subjectAlternativeNameExtension = new SubjectAlternativeNameExtension(generalNames);
//            x509Cert.set(SubjectAlternativeNameExtension.IDENT, subjectAlternativeNameExtension);

            //crl
//            GeneralName crlName = new GeneralName(new URIName("http://www.c1.com:8082/a.crl"));
//            GeneralNames generalNames2 = new GeneralNames().add(crlName);
//            DistributionPoint distributionPoint = new DistributionPoint(generalNames2, null, null);
//            List<DistributionPoint> a = new ArrayList<>();
//            a.add(distributionPoint);
//            CRLDistributionPointsExtension crlDistributionPointsExtension = new CRLDistributionPointsExtension(a);
//            x509Cert.set(CRLDistributionPointsExtension.IDENT, crlDistributionPointsExtension);


            X509CertInfo x509CertInfo = (X509CertInfo)x509Cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
            int id=1;
            String key=KeyouUtils.numberToString(id);
            String psB64Certificate = KeyouUtils.signByKey(x509CertInfo, key);

            return ResultData.success(psB64Certificate);

        } catch (IOException ioException) {
            ioException.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException | CertificateException | KeyStoreException e) {
            log.error(me+"server 证书库读取失败");
            e.printStackTrace();
        } catch (InvalidKeyException | NoSuchProviderException e) {
            log.error(me+"cer 签名失败");
            e.printStackTrace();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
//        return "error";
        return ResultData.error();
    }


}
