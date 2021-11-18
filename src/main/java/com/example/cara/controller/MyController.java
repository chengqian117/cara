package com.example.cara.controller;

import com.example.cara.config.ResultData;
import com.example.cara.config.ResultViewModel;
import com.example.cara.entity.pojo.TestThread;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.*;

//@RestController
//@RequestMapping("/my")
public class MyController {

    static public Map<String,Object> threadGroup=new Hashtable<>();
    static String name="a0";


    @GetMapping("/get")
    public ResultViewModel get(){
        try {
            TestThread testThread = new TestThread();
            FutureTask<Object> fu=new FutureTask<Object>(testThread);
            Object object = threadGroup.get(name);
            ExecutorService executorService;
            if(object==null||object instanceof ExecutorService){
                executorService=(ExecutorService) object;
            }else{
                return ResultData.error(1,"stop");
            }
            if(executorService==null){
                executorService = new ThreadPoolExecutor(1000,15000,2,TimeUnit.SECONDS,
                        new ArrayBlockingQueue<Runnable>(15000),Executors.defaultThreadFactory(),
                        new ThreadPoolExecutor.CallerRunsPolicy());
                threadGroup.put(name,executorService);
            }
            executorService.submit(fu);
            while (!fu.isDone()){
                Thread.sleep(1000L);
//                System.out.println("等待返回");
            }
            Object o = fu.get();
            return (ResultViewModel)o;
        }catch (Exception exception){
            exception.printStackTrace();
        }

        return ResultData.success("hello word");
    }
    @GetMapping("/stop")
    public ResultViewModel stop(){
        try{
            Object object = threadGroup.get(name);
            ExecutorService executorService;
            if(object instanceof ExecutorService){
                executorService=(ExecutorService) object;
            }else{
                return ResultData.error(1,"stop agin");
            }
            executorService.shutdownNow();
            threadGroup.put(name,false);
        }catch(Exception exception){
            exception.printStackTrace();
        }
        return ResultData.success("hello word");
    }
}
