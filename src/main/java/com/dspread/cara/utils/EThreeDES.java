package com.dspread.cara.utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;

/**
 * @program: TMS
 * @description:
 * @author: Mr.Yang
 * @create: 2021-06-25 17:34
 **/
public class EThreeDES {

    private static final String Algorithm = "DESede"; //定义 加密算法,可用 DES,DESede,Blowfish

    //keybyte为加密密钥，长度为24字节
    //src为被加密的数据缓冲区（源）

    //3DES加密
    public static byte[] encryptMode(byte[] keybyte, byte[] src) {
        try {
            //生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);

            //加密
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.ENCRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    //keybyte为加密密钥，长度为24字节
    //src为加密后的缓冲区

    //3DES解密
    public static byte[] decryptMode(byte[] keybyte, byte[] src) {
        try {
            //生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);

            //解密
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.DECRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    //转换成十六进制字符串
    public static String byte2hex(byte[] b) {
        String hs="";
        String stmp="";

        for (int n=0;n<b.length;n++) {
            stmp=(Integer.toHexString(b[n] & 0XFF));
            if (stmp.length()==1) hs=hs+"0"+stmp;
            else hs=hs+stmp;
            if (n<b.length-1)  hs=hs+":";
        }
        return hs.toUpperCase();
    }

    //转为base64
    public String enBase64(byte[] bparm) throws IOException {
        BASE64Encoder enc=new BASE64Encoder();
        String bdnParm = enc.encodeBuffer(bparm);
        return bdnParm;
    }

    //从BASE64反转回来
    public byte[] deBase64(String parm) throws IOException {
        BASE64Decoder dec=new BASE64Decoder();
        byte[] dnParm = dec.decodeBuffer(parm);
        return dnParm;
    }



    public static String replace(String source, String oldString,
                                 String newString) {
        StringBuffer output = new StringBuffer();
        int lengthOfSource = source.length();
        int lengthOfOld = oldString.length();
        int posStart = 0;
        int pos; //
        while ( (pos = source.indexOf(oldString, posStart)) >= 0) {
            output.append(source.substring(posStart, pos));
            output.append(newString);
            posStart = pos + lengthOfOld;
        }
        if (posStart < lengthOfSource) {
            output.append(source.substring(posStart));
        }
        return output.toString();
    }




    /**
     * 3DES解密
     * @param toThreeDES
     * @return
     */
    public static String deThreeDES(String toThreeDES){
        String deThreeDes="";
        if (toThreeDES==null || toThreeDES.equals(""))
        {
            deThreeDes="";
        }
        else
        {
            try{
                EThreeDES edes = new EThreeDES();
                String key_VALUE = "A314BA5A3C85E86KK887WSWS";
                byte[] keyBytes = key_VALUE.getBytes();

                byte[] toBASE64ToStr = edes.deBase64(toThreeDES);
                byte[] toWK_DESToStr = EThreeDES.decryptMode(keyBytes, toBASE64ToStr);
                deThreeDes = new String(toWK_DESToStr,"utf-8");
            }
            catch(Exception ex)
            {
                //System.out.println("3DES解密出错!!!"+ex.getMessage());
            }
        }

        return deThreeDes;
    }
    public static void main(String[] args) throws IOException
    {


    }

}
