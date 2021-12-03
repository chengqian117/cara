package com.dspread.cara.controller;

import com.dspread.cara.common.CaConfig;
import com.dspread.cara.config.ResultData;
import com.dspread.cara.config.ResultViewModel;
import com.dspread.cara.utils.CaUtils;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import sun.security.x509.X509CertImpl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Base64;

@RestController
@RequestMapping("/ca")
@Api(value = "ca")
@Slf4j
@Profile("dev")
public class CaController {

    @Autowired
    CaConfig caConfig;


    @ApiOperation(value = "下载根证书（公钥）",httpMethod = "GET")
    @GetMapping("downloadRootCer")
    public ResultViewModel downloadRootCer(){
        String me="CA证书 downloadRootCer---------";
        log.info(me+caConfig.getPath());
        String fileName=caConfig.getPath()+ File.separator+caConfig.getRootPath()+File.separator+caConfig.getRootAlias()+".cer";
        fileName=CaUtils.normalizePath(fileName);
        File file = new File(fileName);
        try{
            FileInputStream in = new FileInputStream(file);
            byte[] bytes=new byte[(int)file.length()];
            in.read(bytes);


            X509CertImpl x509Cert = new X509CertImpl(bytes);

            String psB64Certificate = Base64.getEncoder().encodeToString(x509Cert.getEncoded());
            psB64Certificate= CaUtils.splitString(psB64Certificate,64);
            psB64Certificate="-----BEGIN CERTIFICATE-----\n"+psB64Certificate+"\n-----END CERTIFICATE-----\n";

//            response.setContentType("application/force-download");
//            response.setContentType("multipart/form-data");
//            response.setHeader("Access-Control-Expose-Headers", "Content-Disposition");
//            // 设置文件名
//            response.addHeader("Content-Disposition", "attachment;fileName=" + caConfig.getRootAlias()+".cer");
//            ServletOutputStream outputStream = response.getOutputStream();
//            outputStream.write(psB64Certificate.getBytes());
//            outputStream.flush();
//            outputStream.close();
            return ResultData.success(psB64Certificate);
//            return psB64Certificate;
        } catch (FileNotFoundException e) {
            log.error(me+"文件未找到");
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            log.error(me+"文件解析异常");
            e.printStackTrace();
        } catch (CertificateException e) {
            log.error(me+"文件解析异常");
            e.printStackTrace();
        } catch (IOException ioException) {
            log.error(me+"流数据异常");
            ioException.printStackTrace();
        }
//        return "error";
        return ResultData.error();
    }

    @ApiOperation(value = "下载二级证书（公钥）",httpMethod = "GET")
    @GetMapping("downloadServerCer")
    public ResultViewModel downloadServerCer(@RequestParam(value = "serAlias", required = true) String serAlias,
                                    @RequestParam(value = "password", required = false) String password){
        String me="CA证书 downloadServerCer---------";
        log.info(me+caConfig.getPath());
        String serverP12Path = caConfig.getPath() + File.separator + caConfig.getServerPath()
                + File.separator + serAlias + File.separator + serAlias + "." + caConfig.getKeyStoreSuffix();
        serverP12Path = CaUtils.normalizePath(serverP12Path);
        try{
            FileInputStream in = new FileInputStream(serverP12Path);
            KeyStore ks = KeyStore.getInstance("jks");
            ks.load(in, password.toCharArray());
            java.security.cert.Certificate c1 = ks.getCertificate(serAlias);
            X509CertImpl serverCer = new X509CertImpl(c1.getEncoded());

            String psB64Certificate2 = Base64.getEncoder().encodeToString(serverCer.getEncoded());
            psB64Certificate2= CaUtils.splitString(psB64Certificate2,64);

            psB64Certificate2="-----BEGIN CERTIFICATE-----\n"+psB64Certificate2+"\n-----END CERTIFICATE-----";
            return ResultData.success(psB64Certificate2);
//            return psB64Certificate2;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return ResultData.error();
//        return "error";
    }

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
