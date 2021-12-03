package com.dspread.cara.exception;

import com.dspread.cara.config.ResultViewModel;
import lombok.Getter;

/**
 * @author Mr.Yang
 * Created at 2018/8/24.
 */
@Getter
public class CustomException extends RuntimeException{
    private final ResultViewModel<?> resultJson;

    public CustomException(ResultViewModel resultJson) {
        this.resultJson = resultJson;
    }
}
