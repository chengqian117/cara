package com.dspread.cara;

import org.junit.Test;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class LockTest {

    @Test
    public void lock1(){
        Lock lock=new ReentrantLock();
        Condition condition = lock.newCondition();

        Thread a=new Thread(()->{
            System.out.println("a");
            lock.lock();
            System.out.println("a2");
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            lock.unlock();
        });

        Thread b=new Thread(()->{
            System.out.println("b");
            lock.lock();
            System.out.println("b2");
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });
        a.start();
        b.start();

        try{
            Thread.sleep(15000);
        }catch(Exception exception){
            exception.printStackTrace();
        }


    }
}
