package com.dspread.cara.exception;

/**
 * @program: TMS
 * @description: 自定义异常
 * @author: Mr.Yang
 * @create: 2021-05-28 18:51
 **/
public class XjxccException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private String msg;
    private int code = 500;

    public XjxccException(String msg) {
        super(msg);
        this.msg = msg;
    }
    public XjxccException(String msg, Throwable e) {
        super(msg, e);
        this.msg = msg;
    }
    public XjxccException(String msg, int code) {
        super(msg);
        this.msg = msg;
        this.code = code;
    }
    public XjxccException(String msg, int code, Throwable e) {
        super(msg, e);
        this.code = code;
    }
    public String getMsg() {
        return msg;
    }
    public void setMsg(String msg) {
        this.msg = msg;
    }
    public int getCode() {
        return code;
    }
    public void setCode(int code) {
        this.code = code;
    }
}
