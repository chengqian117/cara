
package com.example.cara.config.db;

import com.alibaba.druid.filter.Filter;
import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.wall.WallConfig;
import com.alibaba.druid.wall.WallFilter;
import com.example.cara.config.properties.DataSourceProperties;
import org.springframework.context.annotation.Bean;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * DruidDataSource
 *
 * @since 1.0.0
 */
public class DynamicDataSourceFactory {

    public static DruidDataSource buildDruidDataSource(DataSourceProperties properties) {
        List<Filter> filters = new ArrayList<>();
//        filters.add(wallFilter());

        DruidDataSource druidDataSource = new DruidDataSource();
        //druidDataSource.setFilters(properties.getFilters());
        druidDataSource.setProxyFilters(filters);

        druidDataSource.setDriverClassName(properties.getDriverClassName());
        druidDataSource.setUrl(properties.getUrl());
        druidDataSource.setUsername(properties.getUsername());
        druidDataSource.setPassword(properties.getPassword());

        druidDataSource.setInitialSize(properties.getInitialSize());
        druidDataSource.setMaxActive(properties.getMaxActive());
        druidDataSource.setMinIdle(properties.getMinIdle());
        druidDataSource.setMaxWait(properties.getMaxWait());
        druidDataSource.setTimeBetweenEvictionRunsMillis(properties.getTimeBetweenEvictionRunsMillis());
        druidDataSource.setMinEvictableIdleTimeMillis(properties.getMinEvictableIdleTimeMillis());
        druidDataSource.setMaxEvictableIdleTimeMillis(properties.getMaxEvictableIdleTimeMillis());
        druidDataSource.setValidationQuery(properties.getValidationQuery());
        druidDataSource.setValidationQueryTimeout(properties.getValidationQueryTimeout());
        druidDataSource.setTestOnBorrow(properties.isTestOnBorrow());
        druidDataSource.setTestOnReturn(properties.isTestOnReturn());
        druidDataSource.setPoolPreparedStatements(properties.isPoolPreparedStatements());
        druidDataSource.setMaxOpenPreparedStatements(properties.getMaxOpenPreparedStatements());
        druidDataSource.setSharePreparedStatements(properties.isSharePreparedStatements());

        try {

            druidDataSource.init();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return druidDataSource;
    }


//    @Bean

    public static WallConfig wallConfig(){

        WallConfig config =new WallConfig();

        config.setMultiStatementAllow(true);//允许一次执行多条语句

        config.setNoneBaseStatementAllow(true);//允许非基本语句的其他语句

        return config;

    }
    @Bean

    public static WallFilter wallFilter(){

        WallFilter wallFilter=new WallFilter();

        wallFilter.setConfig(wallConfig());

        return wallFilter;

    }
}