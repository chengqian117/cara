package com.dspread.cara.utils;

import java.io.File;

/**
 * @program: TMS
 * @description:
 * @author: Mr.Yang
 * @create: 2021-06-16 13:16
 **/
public class Constant {
    /*******************************git连接秘钥**************************************/
    public static final String GIT_CONNECT_PRIKEY_WINDOWS = "D:\\gitkey"+ File.separator +"id_rsa";
    public static final String GIT_CONNECT_PRIKEY_LINUX = File.separator +"usr"+File.separator+"tms"+File.separator+"gitkey"+File.separator+"id_rsa";

    public static final String GIT_LOCAL_REPOSITORY_WINDOWS = "D:\\test1";
    public static final String GIT_LOCAL_REPOSITORY_LINUX = File.separator +"usr"+File.separator+"local"+File.separator+"gitku";

    public static final String GIT_LOCAL_REPOSITORY_WINDOWS_GEN = "D:\\test1\\";
    public static final String GIT_LOCAL_REPOSITORY_LINUX_GEN = File.separator +"usr"+File.separator+"local"+File.separator+"gitku"+File.separator;
}
