package com.example.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;

// /login 요청을 할 때 username, password 를 전송하면 이 필터가 동작함 ( usernamepasswodAuthenticationFilter )
// 하지만 securityconfig 에서 formLogin을 disable 시켰기 때문에 동작하지 않음. 그래서 이 필터를 다시 securityconfig 에 등록해줘야 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청 시 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");
        // 1. username, password 받아서
        try {
            BufferedReader br = request.getReader();
            String input = null;
            while((input = br.readLine()) != null) {
                System.out.println(input);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 2. 정상인지 로그인 시도를 해봄. authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출이 됨
        // PrincipalDetailsService의 loadUserByUsername() 메서드가 실행됨
        return super.attemptAuthentication(request, response);
    }

}
