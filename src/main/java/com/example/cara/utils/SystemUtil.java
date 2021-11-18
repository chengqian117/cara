package com.example.cara.utils;

/**
 * @program: TMS
 * @description: 操作系统
 * @author: Mr.Yang
 * @create: 2021-06-16 13:14
 **/
public class SystemUtil {
    public static boolean isWindows() {
        return System.getProperties().getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1;
    }
    public static boolean isLinux() {
        return System.getProperties().getProperty("os.name").toUpperCase().indexOf("LINUX") != -1;
    }
}
