package com.example.cara.controller;

import cn.hutool.captcha.generator.RandomGenerator;
import com.example.cara.common.CaConfig;
import com.example.cara.config.ResultData;
import com.example.cara.config.ResultViewModel;
import com.example.cara.entity.pojo.KeyouResult;
import com.example.cara.utils.CaUtils;
import com.example.cara.utils.KeyouUtils;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

@RestController
@RequestMapping("/cara")
@Api(value = "cara")
@Slf4j
public class CaraController {

    @Autowired
    CaConfig caConfig;

    @ApiOperation(value = "下载根证书（公钥）",httpMethod = "GET")
    @GetMapping("downloadRootCer")
    public ResultViewModel downloadRootCer(){
        String me="CA证书 downloadRootCer---------";
        log.info(me);
        //有效年数
        int years=10;
        try{
            Socket socket = KeyouUtils.getInstance();
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
            final byte[] response = KeyouUtils.call(socket, message);

            KeyouResult keyouResult = KeyouUtils.dealResponse(response, true, headString);
            boolean success = keyouResult.isSuccess();
            if(success){
                byte[] data = keyouResult.getData();
                log.debug("公钥:{}", Base64.getEncoder().encodeToString(data));
                // 取得公钥  for PKCS#1
                RSAPublicKeyStructure asn1pub = new RSAPublicKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(data));
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(asn1pub.getModulus(), asn1pub.getPublicExponent());
                KeyFactory keyFactory= KeyFactory.getInstance("RSA");
                PublicKey aPublic = keyFactory.generatePublic(rsaPublicKeySpec);

                final String commonNameRoot = "www.dspread.com";
                final String organizationalUnitRoot = "CARA认证中心";
                final String organizationRoot = "CARA认证中心";
                final String cityRoot = "beijing";
                final String stateRoot = "beijing";
                final String countryRoot = "CN";

                X500Name issuer = new X500Name(commonNameRoot, organizationalUnitRoot, organizationRoot, cityRoot, stateRoot, countryRoot);
                //设置cer内容
                X509CertImpl x509Cert = CaUtils.createCer(issuer, 365*years, aPublic,issuer);
                X509CertInfo x509CertInfo = (X509CertInfo)x509Cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

                String result= KeyouUtils.signByRoot(x509CertInfo);
                log.debug("\n"+result);
                return ResultData.success(result);
            }else {
                String error = keyouResult.getError();
                String notFoundCode="12";
                if(notFoundCode.equals(error)){
                    throw new RuntimeException("根秘钥未初始化");
                }
            }
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return ResultData.error();
    }

//    @ApiOperation(value = "下载二级证书（公钥）",httpMethod = "GET")
//    @GetMapping("downloadServerCer")
//    public ResultViewModel downloadServerCer(@RequestParam(value = "serAlias", required = true) String serAlias,
//                                    @RequestParam(value = "password", required = false) String password){
//        String me="CA证书 downloadServerCer---------";
//        log.info(me+caConfig.getPath());
//        String serverP12Path = caConfig.getPath() + File.separator + caConfig.getServerPath()
//                + File.separator + serAlias + File.separator + serAlias + "." + caConfig.getKeyStoreSuffix();
//        serverP12Path = CaUtils.normalizePath(serverP12Path);
//        try{
//            FileInputStream in = new FileInputStream(serverP12Path);
//            KeyStore ks = KeyStore.getInstance("jks");
//            ks.load(in, password.toCharArray());
//            java.security.cert.Certificate c1 = ks.getCertificate(serAlias);
//            X509CertImpl serverCer = new X509CertImpl(c1.getEncoded());
//
//            String psB64Certificate2 = Base64.getEncoder().encodeToString(serverCer.getEncoded());
//            psB64Certificate2= CaUtils.splitString(psB64Certificate2,64);
//
//            psB64Certificate2="-----BEGIN CERTIFICATE-----\n"+psB64Certificate2+"\n-----END CERTIFICATE-----";
//            return ResultData.success(psB64Certificate2);
////            return psB64Certificate2;
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (IOException ioException) {
//            ioException.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//        return ResultData.error();
////        return "error";
//    }
//
//    @PostMapping("signByServer")
//    @ApiOperation(value = "通过二级服务签字",httpMethod = "POST")
//    public ResultViewModel signByServer( @RequestBody SignDto signDto) {
//        String csr=signDto.getFile();
//        String serAlias=signDto.getSerAlias();
//        String cliAlias=signDto.getCliAlias();
//        String password=signDto.getPassword();
//
//        String me = serAlias+" CA证书 signByServer---------" + signDto.toString() + "------";
//        log.info(me);
//        log.debug(me);
//
//        log.debug(csr);
//        if (csr == null || serAlias == null || StringUtils.isEmpty(serAlias)) {
//            log.error(me + csr );
//            return ResultData.error();
////            return "error";
//        }
//        if (StringUtils.isEmpty(password)) {
//            password = caConfig.getDefaultPw();
//        }
//        try {
////            csr = URLUtil.decode(csr);
//            csr = csr.replaceAll("\n", "")
////                    .replaceAll("%2", "")
//                    .replaceAll("\r", "")
//                    .replaceAll(" ", "")
//                    .replaceAll("-----[A-Z ]*-----", "");
//
//            PKCS10 pkcs10 = new PKCS10(Base64.getDecoder().decode(csr));//解析成P10对象
//            //获取P10中定义的证书主题
//            X500Name subject = pkcs10.getSubjectName();
//            //获取算法
//            String alg = pkcs10.getSigAlg();
//            //获取P10中的公钥，这里获取的是一个公钥结构体，不是一个单纯的公钥(PS：我们C开发说的，需要用C去解析成单纯的公钥，API没有提供方法)
//            PublicKey publicKey = pkcs10.getSubjectPublicKeyInfo();
//
//            String serverP12Path = caConfig.getPath() + File.separator + caConfig.getServerPath()
//                    + File.separator + serAlias + File.separator + serAlias + "." + caConfig.getKeyStoreSuffix();
//            serverP12Path = CaUtils.normalizePath(serverP12Path);
//            FileInputStream in = new FileInputStream(serverP12Path);
//            KeyStore ks = KeyStore.getInstance("jks");
//            ks.load(in, password.toCharArray());
//            java.security.cert.Certificate c1 = ks.getCertificate(serAlias);
//            X509CertImpl serverCer = new X509CertImpl(c1.getEncoded());
//            X509CertInfo serverCerInfo = (X509CertInfo) serverCer.get(X509CertImpl.NAME +
//                    "." + X509CertImpl.INFO);
//            PrivateKey privateKey = (PrivateKey) ks.getKey(serAlias, password.toCharArray());
//
//
//            //设置cer内容
//            X509CertImpl x509Cert = CaUtils.createCer(subject, 365, publicKey, (X500Name) serverCerInfo.get(X509CertInfo.SUBJECT));
//
//
//            KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
//            keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
//            keyUsageExtension.set(KeyUsageExtension.KEY_ENCIPHERMENT, true);
//
//            x509Cert.set(KeyUsageExtension.IDENT, keyUsageExtension);
//
//            Vector<ObjectIdentifier> objectIdentifiers = new Vector<>();
//            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1}));
//            objectIdentifiers.add(ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2}));
//            ExtendedKeyUsageExtension extendedKeyUsageExtension = new ExtendedKeyUsageExtension(objectIdentifiers);
//
//            x509Cert.set(ExtendedKeyUsageExtension.IDENT, extendedKeyUsageExtension);
//
//            GeneralNameInterface dnsName = new DNSName("www.c1.com");
//            GeneralName generalName = new GeneralName(dnsName);
//            GeneralNames generalNames = new GeneralNames().add(generalName);
//            SubjectAlternativeNameExtension subjectAlternativeNameExtension = new SubjectAlternativeNameExtension(generalNames);
//            x509Cert.set(SubjectAlternativeNameExtension.IDENT, subjectAlternativeNameExtension);
//
//            GeneralName crlName = new GeneralName(new URIName("http://www.c1.com:8082/a.crl"));
//            GeneralNames generalNames2 = new GeneralNames().add(crlName);
//            DistributionPoint distributionPoint = new DistributionPoint(generalNames2, null, null);
//            List<DistributionPoint> a = new ArrayList<>();
//            a.add(distributionPoint);
//            CRLDistributionPointsExtension crlDistributionPointsExtension = new CRLDistributionPointsExtension(a);
//            x509Cert.set(CRLDistributionPointsExtension.IDENT, crlDistributionPointsExtension);
//
//            x509Cert.sign(privateKey, alg);
//
//            //拼接证书链
//            String psB64Certificate = Base64.getEncoder().encodeToString(x509Cert.getEncoded());
//            psB64Certificate= CaUtils.splitString(psB64Certificate,64);
//
//            psB64Certificate="-----BEGIN CERTIFICATE-----\n"+psB64Certificate+"\n-----END CERTIFICATE-----";
//
////            String psB64Certificate2 = Base64.getEncoder().encodeToString(serverCer.getEncoded());
////            psB64Certificate2= CaUtils.splitString(psB64Certificate2,64);
////
////            psB64Certificate2="-----BEGIN CERTIFICATE-----\n"+psB64Certificate2+"\n-----END CERTIFICATE-----";
////
////            psB64Certificate=psB64Certificate+"\n"+psB64Certificate2;
//
////            String rootCerFilePath=caConfig.getPath()+ File.separator+caConfig.getRootPath()+File.separator+caConfig.getRootAlias()+".cer";
////            rootCerFilePath=CaUtils.normalizePath(rootCerFilePath);
////            File rootCerFile = new File(rootCerFilePath);
////            FileInputStream rootCerFileIN = new FileInputStream(rootCerFile);
//
////            byte[] rootCerBytes=new byte[(int)rootCerFile.length()];
////            rootCerFileIN.read(rootCerBytes);
////            X509CertImpl rooCer = new X509CertImpl(rootCerBytes);
////            String rootCerBase64 = Base64.getEncoder().encodeToString(rooCer.getEncoded());
////            rootCerBase64= CaUtils.splitString(rootCerBase64,64);
//
////            rootCerBase64="-----BEGIN CERTIFICATE-----\n"+rootCerBase64+"\n-----END CERTIFICATE-----";
//
////            psB64Certificate=psB64Certificate+"\n"+rootCerBase64;
//
//            //导出证书
////            response.setContentType("application/force-download");
////            response.setContentType("multipart/form-data");
////            response.setHeader("Access-Control-Expose-Headers", "Content-Disposition");
////            // 设置文件名
////            response.addHeader("Content-Disposition", "attachment;fileName=" + cliAlias+".cer");
////            ServletOutputStream outputStream = response.getOutputStream();
////            outputStream.write(psB64Certificate.getBytes());
////            outputStream.flush();
////            outputStream.close();
////            return psB64Certificate;
//            return ResultData.success(psB64Certificate);
//
//        } catch (IOException ioException) {
//            ioException.printStackTrace();
//        } catch (SignatureException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (UnrecoverableKeyException | CertificateException | KeyStoreException e) {
//            log.error(me+"server 证书库读取失败");
//            e.printStackTrace();
//        } catch (InvalidKeyException | NoSuchProviderException e) {
//            log.error(me+"cer 签名失败");
//            e.printStackTrace();
//        }
////        return "error";
//        return ResultData.error();
//    }


}
