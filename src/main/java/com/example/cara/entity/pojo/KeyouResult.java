package com.example.cara.entity.pojo;

import lombok.Data;

/**
 * 科友加密机返回数据封装
 * @author cq
 */
@Data
public class KeyouResult {

    private String head;
    private String status;
    private String error;
    private boolean success;
    private int length;
    private byte[] data;
}
