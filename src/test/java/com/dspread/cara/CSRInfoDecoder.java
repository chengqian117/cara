package com.dspread.cara;


import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.asn1.x500.X500Name;

import java.io.*;
import java.security.Security;

@Slf4j
public class CSRInfoDecoder {


    private static final String COUNTRY = "2.5.4.6";

    private static final String STATE = "2.5.4.8";

    private static final String LOCALE = "2.5.4.7";

    private static final String ORGANIZATION = "2.5.4.10";

    private static final String ORGANIZATION_UNIT = "2.5.4.11";

    private static final String COMMON_NAME = "2.5.4.3";

    public static void main(String[] args) {

        String fileName="D:\\ssl_k\\root\\server1.csr";

        PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(fileName);
        X500Name x500Name = csr.getSubject();
        System.out.println("x500Name is: " + x500Name + "\n");

// country is 2.5.4.6

        System.out.println("COUNTRY: " + getX500Field(COUNTRY, x500Name));
//
// state is 2.5.4.8

        System.out.println("STATE: " + getX500Field(STATE, x500Name));

// locale is 2.5.4.7

        System.out.println("LOCALE: " + getX500Field(LOCALE, x500Name));
        System.out.println("ORGANIZATION_UNIT: " + getX500Field(ORGANIZATION_UNIT, x500Name));
        System.out.println("ORGANIZATION: " + getX500Field(ORGANIZATION, x500Name));
        System.out.println("COMMON_NAME: " + getX500Field(COMMON_NAME, x500Name));
        try {
            RSAKeyParameters pubkey =   (RSAKeyParameters) PublicKeyFactory.createKey(csr.getSubjectPublicKeyInfo());
            System.out.println(pubkey.getModulus().toString(16));
//            SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();
//            ASN1Primitive asn1Primitive = subjectPublicKeyInfo.parsePublicKey();
//            byte[] encoded = asn1Primitive.getEncoded("DER");
//
//            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encoded);
//            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
//
//            PublicKey aPublic = keyfactory.generatePublic(x509EncodedKeySpec);
//            System.out.println(aPublic);
//            for (int i = 0; i < s.length(); i++) {
//                String b2=s.substring(i,i+1);
//                byte b;
//                if (b2.compareTo("8") >= 0) {
//                    b = Byte.valueOf(Integer.toString(Integer.parseInt(strings[i], 16) - 256));
//                } else {
//                    b = Byte.valueOf(Integer.toString(Integer.parseInt(strings[i], 16)));
//                }
//
//            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));

        String retVal = null;

        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }

        return retVal;

    }

    private static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String fileName) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        PKCS10CertificationRequest csr = null;

        ByteArrayInputStream pemStream = null;

        try {
            File file = new File(fileName);
            FileInputStream in = new FileInputStream(file);
            byte[] bytes=new byte[(int)file.length()];
            in.read(bytes);
            pemStream = new ByteArrayInputStream(bytes);

        } catch (UnsupportedEncodingException ex) {
            log.error("UnsupportedEncodingException, convertPemToPublicKey", ex);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));

        PEMParser pemParser = new PEMParser(pemReader);

        try {
            Object parsedObj = pemParser.readObject();

            System.out.println("PemParser returned: " + parsedObj);

            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;

            }

        } catch (IOException ex) {
            log.error("IOException, convertPemToPublicKey", ex);

        }

        return csr;

    }


//    private String toPEM(Object key) {
//        StringWriter sw = new StringWriter();
//
//        PEMWriter pem = new PEMWriter(sw);
//
//        try {
//            pem.writeObject(key);
//
//            pem.close();
//
//        } catch (IOException e) {
//            System.out.printf("IOException: %s%n", e);
//
//        }
//
//        return sw.toString();
//
//    }
    }
