package com.dspread.cara.entity.pojo;

import com.dspread.cara.config.ResultData;
import com.dspread.cara.config.ResultViewModel;

import java.util.concurrent.Callable;

public class TestThread implements Callable<Object> {


    @Override
    public ResultViewModel call() throws Exception {
        System.out.println("进入" + Thread.currentThread().getId());
        try {
            Thread.sleep(60000);
        } catch (InterruptedException e) {
            e.printStackTrace();
            return ResultData.error(1, "zd");
        }
        return ResultData.success("hello word");
    }
}
