package com.dspread.cara.utils;

/**
 * @program: TMS
 * @description:
 * @author: Mr.Yang
 * @create: 2021-06-10 18:39
 **/
public class XORUtils {
    private final static String HEX = "0123456789ABCDEFFEDCBA9876543210";
    static final String HEXES = "0123456789ABCDEF";
    /**
     * 异或算法加密/解密
     *
     * @return 返回解密/加密后的数据
     */
    //16 byte xor
    public static String xor16(byte[] src1, byte[] src2){
        byte[] results = new byte[16];
        for (int i = 0; i < results.length; i++){
            results[i] = (byte)(src1[i] ^ src2[i]);
        }
        return byteArray2Hex(results);
    }
    public static String byteArray2Hex( byte [] raw ) {
        if ( raw == null ) {
            return null;
        }
        final StringBuilder hex = new StringBuilder( 2 * raw.length );
        for ( final byte b : raw ) {
            hex.append(HEX.charAt((b & 0xF0) >> 4))
                    .append(HEX.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    public static String byteArray2Hex( byte [] raw , int len) {
        if ( raw == null ) {
            return null;
        }
        final StringBuilder hex = new StringBuilder( 2 * len );
        for (int i = 0; i < len; i++) {
            hex.append(HEXES.charAt((raw[i] & 0xF0) >> 4))
                    .append(HEXES.charAt((raw[i] & 0x0F)));
        }
        return hex.toString();
    }
    /**
     * 16进制格式的字符串转成16进制byte 44 --> byte 0x44
     *
     * @param hexString
     * @return
     */
    public static byte[] HexStringToByteArray(String hexString) {//
        if (hexString == null || hexString.equals("")) {
            return new byte[]{};
        }
        if (hexString.length() == 1 || hexString.length() % 2 != 0) {
            hexString = "0" + hexString;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }
    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }
}
