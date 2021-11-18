package com.example.cara.config;

import com.alibaba.fastjson.annotation.JSONField;
import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * @program: TMS
 * @description:
 * @author: Mr.Yang
 * @create: 2021-06-14 23:13
 **/
public class ResultViewModel<T> {
    private Integer code;
    @JSONField(serialize = false)
    @JsonIgnore
    private String message;
    private T data;

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
