
package com.example.cara.entity.pojo;

import com.baomidou.mybatisplus.core.metadata.IPage;
import org.apache.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

/**
 * 返回数据
 */
public class R extends HashMap<String, Object> {
    private static final long serialVersionUID = 1L;

    public R() {
        put("code", 0);
        put("msg", "success");
    }

    public static R error() {
        return error(HttpStatus.SC_INTERNAL_SERVER_ERROR, "未知异常，请联系管理员");
    }

    public static R error(String msg) {
        return error(HttpStatus.SC_INTERNAL_SERVER_ERROR, msg);
    }

    public static R error(int code, String msg) {
        R r = new R();
        r.put("code", code);
        r.put("msg", msg);
        return r;
    }

    public static R ok(String msg) {
        R r = new R();
        r.put("msg", msg);
        return r;
    }


    public static R ok(Map<String, Object> map) {
        R r = new R();
        r.putAll(map);
        return r;
    }

    public static R ok(IPage page) {
        R r = new R();
        if (page != null && page.getTotal() > 0) {
            r.put("count", page.getTotal());
            r.put("data", page.getRecords());
            r.put("page", page.getCurrent());
            r.put("size", page.getSize());
        }
        r.setMessage("无记录");
        return r;
    }

    public static R ok() {
        return new R();
    }

    public static R okAdd(String msg) {
        return ok("新增" + msg + "成功！");
    }

    public static R okAdd(String msg, Object data) {
        Map<String, Object> map = new HashMap<>();
        map.put("data", data);
        map.put("msg", "新增" + msg + "成功！");
        return ok(map);
    }

    public static R okEdit(String msg) {
        return ok("修改" + msg + "成功！");
    }

    public static R okDel(String msg) {
        return ok("删除" + msg + "成功！");
    }

    public R put(String key, Object value) {
        super.put(key, value);
        return this;
    }

    private void setMessage(String msg) {
        this.put("msg", msg);
    }
}
