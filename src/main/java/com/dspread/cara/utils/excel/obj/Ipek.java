package com.dspread.cara.utils.excel.obj;

import java.io.Serializable;

/**
 * @program: TMS
 * @description:
 * @author: Mr.Yang
 * @create: 2021-06-10 14:42
 **/
public class Ipek implements Serializable {
    private String strProj;
    private String pos_type;
    private String strPosSn;
    private String strKsn1;
    private String strKsn2;
    private String strKsn3;
    private String strPosIpek1;
    private String strPosIpek2;
    private String strPosIpek3;
    private String chkv1;
    private String chkv2;
    private String chkv3;

    public String getStrProj() {
        return strProj;
    }

    public void setStrProj(String strProj) {
        this.strProj = strProj;
    }

    public String getPos_type() {
        return pos_type;
    }

    public void setPos_type(String pos_type) {
        this.pos_type = pos_type;
    }

    public String getStrPosSn() {
        return strPosSn;
    }

    public void setStrPosSn(String strPosSn) {
        this.strPosSn = strPosSn;
    }

    public String getStrKsn1() {
        return strKsn1;
    }

    public void setStrKsn1(String strKsn1) {
        this.strKsn1 = strKsn1;
    }

    public String getStrKsn2() {
        return strKsn2;
    }

    public void setStrKsn2(String strKsn2) {
        this.strKsn2 = strKsn2;
    }

    public String getStrKsn3() {
        return strKsn3;
    }

    public void setStrKsn3(String strKsn3) {
        this.strKsn3 = strKsn3;
    }

    public String getStrPosIpek1() {
        return strPosIpek1;
    }

    public void setStrPosIpek1(String strPosIpek1) {
        this.strPosIpek1 = strPosIpek1;
    }

    public String getStrPosIpek2() {
        return strPosIpek2;
    }

    public void setStrPosIpek2(String strPosIpek2) {
        this.strPosIpek2 = strPosIpek2;
    }

    public String getStrPosIpek3() {
        return strPosIpek3;
    }

    public void setStrPosIpek3(String strPosIpek3) {
        this.strPosIpek3 = strPosIpek3;
    }

    public String getChkv1() {
        return chkv1;
    }

    public void setChkv1(String chkv1) {
        this.chkv1 = chkv1;
    }

    public String getChkv2() {
        return chkv2;
    }

    public void setChkv2(String chkv2) {
        this.chkv2 = chkv2;
    }

    public String getChkv3() {
        return chkv3;
    }

    public void setChkv3(String chkv3) {
        this.chkv3 = chkv3;
    }

    @Override
    public String toString() {
        return "Ipek{" +
                "strProj='" + strProj + '\'' +
                ", pos_type='" + pos_type + '\'' +
                ", strPosSn='" + strPosSn + '\'' +
                ", strKsn1='" + strKsn1 + '\'' +
                ", strKsn2='" + strKsn2 + '\'' +
                ", strKsn3='" + strKsn3 + '\'' +
                ", strPosIpek1='" + strPosIpek1 + '\'' +
                ", strPosIpek2='" + strPosIpek2 + '\'' +
                ", strPosIpek3='" + strPosIpek3 + '\'' +
                ", chkv1='" + chkv1 + '\'' +
                ", chkv2='" + chkv2 + '\'' +
                ", chkv3='" + chkv3 + '\'' +
                '}';
    }
}
