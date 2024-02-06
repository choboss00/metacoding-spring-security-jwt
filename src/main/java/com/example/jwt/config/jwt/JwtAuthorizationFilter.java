package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 필터를 가지고 있는데, 필터 중 BasicAuthenticationFilter라는 것이 있다.
// 이 필터는 권한이나 인증이 필요한 특정 주소를 요청했을 때 동작하는 필터이다.
// 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 무시한다.
// 이 필터를 커스터마이징하기 위해서는 BasicAuthenticationFilter를 상속받아서 직접 커스터마이징 해야 한다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소가 요청이 되었을 때 해당 필터를 타게 된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");

        String header = request.getHeader("Authorization");
        // header 가 있는지 확인하는 과정
        if (header == null || !header.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }
        // token 을 가져온 뒤, 원하는 데이터 파싱
        String token = request.getHeader("Authorization").replace("Bearer ", "");
        // username 이 정상적으로 가져온 경우, 서명이 정상적으로 진행되었음
        String username = JWT.require(Algorithm.HMAC512("조익현")).build().verify(token).getClaim("username").asString();

        if (username != null) {
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // jwt 토큰 서명을 통해 정상적으로 인증이 되었으니, 강제로 객체를 만들어줌
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);


        }
        chain.doFilter(request, response);





    }
}
