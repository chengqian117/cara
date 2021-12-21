package com.dspread.cara.controller;

import com.dspread.cara.common.CaConfig;
import com.dspread.cara.config.ResultData;
import com.dspread.cara.config.ResultViewModel;
import com.dspread.cara.utils.CaUtils;
import com.dspread.cara.utils.EccUtils;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import sun.security.pkcs10.PKCS10;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.*;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * @author cq
 */
@RestController
@RequestMapping("/ca/local/ecc")
@Api(value = "ca Ecc离线服务",tags = "ca Ecc离线服务")
@Slf4j
@Profile("dev")
public class EccLocalController {

    @Autowired
    CaConfig caConfig;

    final String commonName = "www.dspread.com";
    final String organizationalUnit = "CARA认证中心";
    final String organization = "CARA认证中心";
    final String city = "beijing";
    final String state = "beijing";
    final String country = "CN";

    @ApiOperation(value = "生成根证书",httpMethod = "POST")
    @PostMapping("initRoot")
    public ResultViewModel initRoot(){

        String alias=caConfig.getRootAlias();
        String password=caConfig.getDefaultPw();

        try{
            X500Name subject = new X500Name(commonName, organizationalUnit, organization, city, state, country);
            boolean root = EccUtils.generateAndExportRoot(alias, password, subject, caConfig.getRootPath());
            if(!root){
                return ResultData.success("根证书生成失败，查看根证书是够已存在");
            }
            EccUtils.exportRootCer(alias,password);
        }catch(Exception exception){
            exception.printStackTrace();
        }
        return ResultData.success("初始化成功");
    }

    @ApiOperation(value = "下载根证书",httpMethod = "GET")
    @GetMapping("downloadRootCer")
    public void downloadRootCer(HttpServletResponse response){
        String me="CA证书 downloadRootCer---------";
        log.info(me+caConfig.getPath());
        String fileName=caConfig.getPath()+ File.separator+caConfig.getRootPath()+File.separator+caConfig.getRootAlias()+".cer";
        fileName=EccUtils.normalizePath(fileName);
        File file = new File(fileName);
        try{
            FileInputStream in = new FileInputStream(file);
            byte[] bytes=new byte[(int)file.length()];
            in.read(bytes);
            String cer=new String(bytes);
            in.close();

            response.setContentType("application/force-download");
            response.setContentType("multipart/form-data");
            response.setHeader("Access-Control-Expose-Headers", "Content-Disposition");
            // 设置文件名
            response.addHeader("Content-Disposition", "attachment;filename=" + caConfig.getRootAlias()+".cer");
            ServletOutputStream outputStream = response.getOutputStream();
            outputStream.write(cer.getBytes());
            outputStream.flush();
            outputStream.close();
        } catch (FileNotFoundException e) {
            log.error(me+"文件未找到");
            e.printStackTrace();
        } catch (IOException ioException) {
            log.error(me+"流数据异常");
            ioException.printStackTrace();
        }
    }


    @PostMapping("signByRoot")
    @ApiOperation(value = "通过二级服务签字",httpMethod = "POST")
    public void signByRoot(@RequestParam MultipartFile file,HttpServletResponse httpServletResponse) {

        String me = " CA证书 signByRoot---------" ;
        log.info(me);
        try {
            byte[] bytes=file.getBytes();
            String s=new String(bytes);
            String sb = s.replaceAll("\n","")
                    .replaceAll("\r","")
                    .replaceAll(" ", "")
                    .replaceAll("-----[A-Z ]*-----","");
            //解析成P10对象
            PKCS10 pkcs10 = new PKCS10(Base64.getDecoder().decode(sb));
            //获取P10中定义的证书主题
            X500Name subject = pkcs10.getSubjectName();
            //获取算法
            String alg = pkcs10.getSigAlg();
            String algDefault="SHA256withECDSA";
            if(!algDefault.equalsIgnoreCase(alg)){
                throw new RuntimeException("加密方式只支持"+algDefault);
            }
            //获取P10中的公钥，这里获取的是一个公钥结构体，不是一个单纯的公钥(PS：我们C开发说的，需要用C去解析成单纯的公钥，API没有提供方法)
            PublicKey publicKey = pkcs10.getSubjectPublicKeyInfo();

            String fileName=caConfig.getPath()+ File.separator+caConfig.getRootPath()+File.separator+caConfig.getRootAlias()+"."+caConfig.getKeyStoreSuffix();
            FileInputStream in = new FileInputStream(fileName);
            KeyStore ks = KeyStore.getInstance("jks");
            ks.load(in, caConfig.getDefaultPw().toCharArray());

            PrivateKey privateKey = (PrivateKey) ks.getKey(caConfig.getRootAlias(), caConfig.getDefaultPw().toCharArray());

            X500Name issuer = new X500Name(commonName, organizationalUnit, organization, city, state, country);
            //设置cer内容
            X509CertImpl x509Cert = EccUtils.createCer(subject, 365*caConfig.getYears(), publicKey, issuer);


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

            x509Cert.sign(privateKey, algDefault);

            byte[] encoded = x509Cert.getEncoded();

            String psB64Certificate = Base64.getEncoder().encodeToString(encoded);
            psB64Certificate= CaUtils.splitString(psB64Certificate,64);

            psB64Certificate="-----BEGIN CERTIFICATE-----\n"+psB64Certificate+"\n-----END CERTIFICATE-----";

            httpServletResponse.setCharacterEncoding("utf-8");
            httpServletResponse.setContentType("application/force-download");
            httpServletResponse.setContentType("multipart/form-data");
            httpServletResponse.setHeader("Access-Control-Expose-Headers", "Content-Disposition");
            String fileName2 = URLEncoder.encode(subject.getCommonName()+".cer", "utf-8");
            // 设置文件名
            httpServletResponse.addHeader("Content-Disposition", "attachment;filename=" +fileName2);
            ServletOutputStream outputStream = httpServletResponse.getOutputStream();
            outputStream.write(psB64Certificate.getBytes());
            outputStream.flush();
            outputStream.close();

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
        }
//        return "error";
//        return ResultData.error();
    }


}
