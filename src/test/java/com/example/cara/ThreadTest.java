package com.example.cara;

import org.junit.jupiter.api.Test;

import java.util.concurrent.*;

public class ThreadTest {

    @Test
    public void a1(){

//        Thread thread=new Thread(()->{
//            System.out.println(Thread.currentThread().getName()+"0");
//            String a="1";
//            for (int i = 0; i < 1000000000; i++) {
//                a+="a"+1;
////                Thread.sleep(1000);
//                System.out.println(i);
//            }
//        });
//        thread.start();
//        thread.interrupt();
        Callable<String> callable= () -> {
            System.out.println(Thread.currentThread().getName()+"0");
            String a="1";
            for (int i = 0; i < 100000; i++) {
                a+="a"+1;
//                Thread.sleep(1000);
                System.out.println(i);
            }
            if(Thread.currentThread().isInterrupted()){
                return "true";
            }
            return a;

        };
//        Thread thread = new Thread(fu);
//        thread.start();
        ExecutorService executorService = Executors.newCachedThreadPool();
        Future<String> fu = executorService.submit(callable);
        new Thread(()->{
            System.out.println(Thread.currentThread().getName()+"1");
            while (!fu.isDone()){
                try {

                    Thread.sleep(1000L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

            }
            try {
                String o = fu.get();
                System.out.println(o);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }).start();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            executorService.awaitTermination(1,TimeUnit.SECONDS);
            executorService.shutdownNow();
            executorService=null;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            Thread.sleep(1000000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
