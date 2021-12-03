package com.dspread.cara.config;

/**
 * @program: TMS
 * @description:
 * @author: Mr.Yang
 * @create: 2021-06-14 23:13
 **/
public class ResultData  {
    /**
     * 请求成功方法01
     * @param object 响应数据
     * @return 视图模型实例
     */
    public static ResultViewModel success(Object object) {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(0);
        resultViewModel.setMessage("请求成功");
        resultViewModel.setData(object);
        return resultViewModel;
    }

    /**
     * 请求成功方法02
     * @return 视图模型实例
     */
    public static ResultViewModel successNoData(String msg) {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(0);
        resultViewModel.setMessage(msg);
        resultViewModel.setData(null);
        return resultViewModel;
    }
    /**
     * 请求成功方法02
     * @return 视图模型实例
     */
    public static ResultViewModel successYesMsg(String msg) {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(2);
        resultViewModel.setMessage(msg);
        resultViewModel.setData(null);
        return resultViewModel;
    }
    /**
     * 请求失败方法01（捕获到的已知异常）
     * @param code 异常编号
     * @param message 异常信息
     * @return 视图模型实例
     */
    public static ResultViewModel error(Integer code, String message) {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(code);
        resultViewModel.setMessage(message);
        resultViewModel.setData(null);
        return resultViewModel;
    }

    /**
     * 请求失败方法02（系统异常）
     * @return 视图模型实例
     */
    public static ResultViewModel error() {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(-1);
        resultViewModel.setMessage("系统异常");
        resultViewModel.setData("系统维护中...");
        return resultViewModel;
    }
    /**
     * 请求失败方法02（系统异常）
     * @return 视图模型实例
     */
    public static ResultViewModel errorLogin() {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(1);
        resultViewModel.setMessage("用户名或密码无效");
        return resultViewModel;
    }
    public static ResultViewModel successLogin(Object object) {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(0);
        resultViewModel.setMessage("登录成功");
        resultViewModel.setData(object);
        return resultViewModel;
    }

    public static ResultViewModel errors(Integer forbidden, String s) {
        ResultViewModel resultViewModel = new ResultViewModel();
        resultViewModel.setCode(forbidden);
        resultViewModel.setMessage(s);
        return resultViewModel;
    }
}
