package com.example.cara.common;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author cq
 */
@Component
@ConfigurationProperties(prefix = "ca.config")
@Data
public class CaConfig {

    private  String path;
    private String rootPath;
    private String rootAlias;
    private String serverPath;
    private String clientPath;
    private String defaultPw="123456";
    private String keyStoreSuffix="p12";

}
