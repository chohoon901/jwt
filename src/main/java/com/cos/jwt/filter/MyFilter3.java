package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰 : cos <- id, pw가 정상적으로 들어와 로그인이 완료되면 토큰을 만들어주고 응답해줌
        // 요청할때마다 header의 Authorization에 value값으로 토큰을 갖고오면
        // 이게 내가 만든게 맞는지만 검증하면 된다.
        if(req.getMethod().equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터3");

            if(headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
