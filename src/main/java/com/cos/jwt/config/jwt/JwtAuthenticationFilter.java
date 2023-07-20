package com.cos.jwt.config.jwt;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있다.
// /login요청해서 username, password post로 전송하면 UsernamePasswordAuthenticationFilter 작동한다.
// 지금은 formlogin disalbe해서 작동안하는 상태. 다시 사용하려면 security config에 등록해야한다.


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청시 로그인 시도를 위해 실행됨
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중");

        // 1. username과 pw 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper(); // ObjectMapper가 json을 파싱해줌
            User user = om.readValue(request.getInputStream(), User.class); // User의 정보를 담아줌
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipaldDetailsService의 loadUserByUsername() 함수가 실행됨
            // authenticationManager에 토큰을 넣어서 던지면 인증을 해준다.
            // 결과적으로 authentication에 User 정보가 담김
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            // authentication객체가 session영역에 저장됨
            // 아래 코드 실행으로 username이 출력됐다는건 로그인이 되었다는 뜻이다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 2. 정상인지 로그인 시도. authenticationManager로 로그인 시도를 하면 PrincipalDetails 서비스 호출
        // 3. loadUserByUsername 실행
        // 4. PrincipalDetails를 세션에 담고(권한 관리를 위함) JWT를 만들어 응답.
        return null;
    }
}
