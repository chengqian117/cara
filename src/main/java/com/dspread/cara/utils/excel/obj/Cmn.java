package com.dspread.cara.utils.excel.obj;

import java.io.Serializable;

/**
 * @program: TMS
 * @description:
 * @author: Mr.Yang
 * @create: 2021-06-09 17:47
 **/
public class Cmn implements Serializable {
    private String proNo;
    private String cusName;
    private String devinceName;
    private int orderNum;
    private String fireWareInfo;
    private String tmk;
    private String strManageRsaPubkey;
    private String strRsaConfigPublicKey;
    private String commonCfg;
    private Boolean t ;

    public String getProNo() {
        return proNo;
    }

    public void setProNo(String proNo) {
        this.proNo = proNo;
    }

    public String getCusName() {
        return cusName;
    }

    public void setCusName(String cusName) {
        this.cusName = cusName;
    }

    public String getDevinceName() {
        return devinceName;
    }

    public void setDevinceName(String devinceName) {
        this.devinceName = devinceName;
    }

    public int getOrderNum() {
        return orderNum;
    }

    public void setOrderNum(int orderNum) {
        this.orderNum = orderNum;
    }


    public String getFireWareInfo() {
        return fireWareInfo;
    }

    public void setFireWareInfo(String fireWareInfo) {
        this.fireWareInfo = fireWareInfo;
    }

    public String getTmk() {
        return tmk;
    }

    public void setTmk(String tmk) {
        this.tmk = tmk;
    }

    public String getStrManageRsaPubkey() {
        return strManageRsaPubkey;
    }

    public void setStrManageRsaPubkey(String strManageRsaPubkey) {
        this.strManageRsaPubkey = strManageRsaPubkey;
    }

    public String getStrRsaConfigPublicKey() {
        return strRsaConfigPublicKey;
    }

    public void setStrRsaConfigPublicKey(String strRsaConfigPublicKey) {
        this.strRsaConfigPublicKey = strRsaConfigPublicKey;
    }

    public String getCommonCfg() {
        return commonCfg;
    }

    public void setCommonCfg(String commonCfg) {
        this.commonCfg = commonCfg;
    }

    public Boolean getT() {
        return t;
    }

    public void setT(Boolean t) {
        this.t = t;
    }

    @Override
    public String toString() {
        return "Cmn{" +
                "proNo='" + proNo + '\'' +
                ", cusName='" + cusName + '\'' +
                ", devinceName='" + devinceName + '\'' +
                ", orderNum=" + orderNum +
                ", fireWareInfo='" + fireWareInfo + '\'' +
                ", tmk='" + tmk + '\'' +
                ", strManageRsaPubkey='" + strManageRsaPubkey + '\'' +
                ", strRsaConfigPublicKey='" + strRsaConfigPublicKey + '\'' +
                ", commonCfg='" + commonCfg + '\'' +
                ", t=" + t +
                '}';
    }
}
