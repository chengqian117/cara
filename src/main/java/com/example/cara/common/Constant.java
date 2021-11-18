package com.example.cara.common;

import org.springframework.beans.factory.annotation.Value;

public class Constant {

    //是否使用influxDb
    public static boolean useInfluxDb;
    @Value("${constant.useInfluxDb}")
    public void setUseInfluxDb(boolean useInfluxDb) {
        Constant.useInfluxDb = useInfluxDb;
    }
}
