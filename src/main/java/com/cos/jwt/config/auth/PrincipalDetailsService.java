package com.cos.jwt.config.auth;

import com.cos.jwt.UserRepository;
import com.cos.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// /login시 호출
// 그러나 formlogin을 disable 해놔서 404뜸
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("principal login");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
