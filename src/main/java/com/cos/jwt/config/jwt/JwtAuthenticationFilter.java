package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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

            // 로그인 진행.
            // PrincipaldDetailsService의 loadUserByUsername() 함수가 실행됨
            // 그 후 값이 정상이면 authentication가 리턴됨(db의 username과 pw가 일치한다.)
            // authenticationManager에 토큰을 넣어서 던지면 인증을 해준다.
            // 결과적으로 authentication에 User 정보가 담김
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            // authentication객체의 임시값이 저장됨
            // 아래 코드 실행으로 username이 출력됐다는건 로그인이 되었다는 뜻이다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());

            // return 될때 authentication객체가 session영역에 저장됨
            // 권한 관리를 security가 대신 해주기때문에 편하려고 하는것이다.
            // 굳이 jwt를 쓰면서 session을 만들 이유가 없으나 오로지 권한처리때문에 session에 넣어준다.
            // 세션이 request부터 response까지만, 굉장히 짧은 기간동안만 사용된다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 2. 정상인지 로그인 시도. authenticationManager로 로그인 시도를 하면 PrincipalDetails 서비스 호출
        // 3. loadUserByUsername 실행
        // 4. PrincipalDetails를 세션에 담고(권한 관리를 위함) JWT를 만들어 응답.
        return null;
    }

    // attemptAuthentication함수 실행 후 인증이 정상적으로 실행되었으면 아래함수 실행
    // jwt로 request한 사용자에게 jwt를 response하면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("인증완료");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // HM512방식
        String jwtToken = JWT.create()
                .withSubject("cos 토큰") // 토큰의 이름. 큰 의미 없다.
                // 만료 시간. 토큰이 유효한 시간. 60000은 60*1000밀리세컨드이므로 아래는 10분이다
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*60)))
                // withClaim은 비공개claim으로써 내가 넣고싶은 키-값 쌍을 막 넣어도 된다.
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos")); // HM256,512의 secret값

        // postman 헤더에 아래값이 추가되어 있음
        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}
