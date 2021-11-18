package com.example.cara.exception;

import com.example.cara.config.ResultData;
import com.example.cara.config.ResultViewModel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author Mr.Yang
 * 异常处理类
 * controller层异常无法捕获处理，需要自己处理
 * Created at 2018/8/27.
 */
@RestControllerAdvice
@Slf4j
public class DefaultExceptionHandler {

    /**
     * 处理所有自定义异常
     *
     * @param e 自定义异常
     * @return 返回自定义异常的ResultJson
     */
    @ExceptionHandler(CustomException.class)
    public ResultViewModel<?> handleCustomException(HttpServletRequest req, CustomException e){
        String uri = req.getRequestURI();
        String params = getRequestData(req);
        log.error("==CustomException== {} {} {} {}", uri, params, e.getResultJson().getMessage(), e.getResultJson().getData());
        return e.getResultJson();
    }

    /**
     * 处理参数校验异常
     *
     * @param e 参数校验异常
     * @return 参数异常提示
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResultViewModel handleMethodArgumentNotValidException(MethodArgumentNotValidException e){
        if (e.getBindingResult().getFieldError() == null) {
            return ResultData.error(1, "参数错误");
        }
        log.error(e.getBindingResult().getFieldError().getField() + e.getBindingResult().getFieldError().getDefaultMessage());
        return ResultData.errors(1, e.getBindingResult().getFieldError().getDefaultMessage());
    }

    private static String getRequestData(HttpServletRequest request) {
        List<String> params = new ArrayList<>();
        Map<String, String[]> paramsMap = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : paramsMap.entrySet()) {
            params.add(entry.getKey() + ":" + String.join(",", entry.getValue()));
        }
        return params.toString();
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResultViewModel handleDataIntegrityViolationException(HttpServletRequest req, DataIntegrityViolationException e) {
        String uri = req.getRequestURI();
        String params = getRequestData(req);
        log.error("==MySQLException== {} {} {}", uri, params, e.getCause().getCause().getMessage());
        return ResultData.error(1, e.getCause().getCause().getMessage());
    }
}
