package com.cos.jwt.config;

import com.cos.jwt.UserRepository;
import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Autowired
    private CorsConfig corsConfig;

    @Autowired
    private UserRepository userRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        return http
                // 세션을 사용하지 않고 STATELESS서버로 만들겠다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsConfig.corsFilter()) // 모든 요청이 corsFilter를 타서 cors정책에서 벗어날 수 있다. 크로스오리진 요청이 와도 다 허용.
                .formLogin().disable() // jwt 사용시 id와 비번으로 폼 로그인을 안함
                .httpBasic().disable() // id와 pw를 사용하는 basic http 로그인 방식을 사용 안함
                .apply(new MyCustomDsl())
                .and()
                .authorizeRequests(authorize -> authorize.antMatchers("/api/v1/user/**")
                        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/manager/**")
                        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/admin/**")
                        .access("hasRole('ROLE_ADMIN')")
                        .anyRequest().permitAll())

                .build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager));
//                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }

}
