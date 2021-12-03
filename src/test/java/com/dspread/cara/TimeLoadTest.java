package com.dspread.cara;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TimeLoadTest implements Serializable {

    @JSONField(ordinal = 1)
    private String projectName;
    @JSONField(ordinal = 2)
    private BigDecimal monday ;//   Mon    周一
    @JSONField(ordinal = 3)
    private BigDecimal tuesday ;//  Tue    周二
    @JSONField(ordinal = 4)
    private BigDecimal wednesday ;//  Wed    周三
    @JSONField(ordinal = 5)
    private BigDecimal thursday ;//  Thu    周四
    @JSONField(ordinal = 6)
    private BigDecimal friday ;// Fri    周五
    @JSONField(ordinal = 7)
    private BigDecimal saturday ;// Sat    周六
    @JSONField(ordinal = 8)
    private BigDecimal sunday ;//  Sun    周日

    public static  void getJson(){
        TimeLoadTest timeLoadTest1 = new TimeLoadTest("DST-TIMESHEET", new BigDecimal("1.0"), new BigDecimal("2.0")
                , new BigDecimal("3.0"), new BigDecimal("1.5")
                , new BigDecimal("0.5"), new BigDecimal("0.0")
                , new BigDecimal("0.0")
        );
        TimeLoadTest timeLoadTest2 = new TimeLoadTest("DST-FCIS V1.x", new BigDecimal("7.0"), new BigDecimal("6.0")
                , new BigDecimal("5.0"), new BigDecimal("6.5")
                , new BigDecimal("7.5"), new BigDecimal("0.0")
                , new BigDecimal("0.0")
        );
        List<TimeLoadTest> list=new ArrayList<>();
        list.add(timeLoadTest1);
        list.add(timeLoadTest2);

        String s = JSON.toJSONString(list);
        System.out.println(s);

    }

    public static void main(String[] args) {
        TimeLoadTest.getJson();
    }

}
