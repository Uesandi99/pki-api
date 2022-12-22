package com.uesandi.pkiApi.filter;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(1)
public class RequestFilter implements Filter {

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        String apiKey = req.getHeader("X-API-Key");
        if(apiKey == null || !apiKey.equals("9ddaa525-bfc2-4f74-92e0-43b7a028aee1")){
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN);
        }
        chain.doFilter(request, response);
    }
}