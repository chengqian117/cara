package com.dspread.cara.filter;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean responseFilter() {
        FilterRegistrationBean filterBean = new FilterRegistrationBean();
        filterBean.setFilter(new AddContentLengthFilter());
        filterBean.setUrlPatterns(Arrays.asList("*"));
        return filterBean;
    }

}
class AddContentLengthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        ContentCachingResponseWrapper cacheResponseWrapper;
        if (!(response instanceof ContentCachingResponseWrapper)) {
            cacheResponseWrapper = new ContentCachingResponseWrapper(response);
        } else {
            cacheResponseWrapper = (ContentCachingResponseWrapper) response;
        }

        filterChain.doFilter(request, cacheResponseWrapper);

        cacheResponseWrapper.copyBodyToResponse();
    }
}