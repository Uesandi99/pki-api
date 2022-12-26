package com.uesandi.pkiApi.filter;

import com.uesandi.pkiApi.constants.Constants;
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

        String apiKey = req.getHeader(Constants.API_KEY_HEADER);
        if(apiKey == null || !apiKey.equals(Constants.API_KEY_HEADER_VALUE)){
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN);
        }
        chain.doFilter(request, response);
    }
}