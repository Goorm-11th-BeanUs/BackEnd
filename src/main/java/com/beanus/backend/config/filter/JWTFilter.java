package com.beanus.backend.config.filter;

import com.beanus.backend.DTO.user.CustomUserDetails;
import com.beanus.backend.domain.user.UserEntity;
import com.beanus.backend.repository.user.UserRepository;
import com.beanus.backend.util.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{

        System.out.println("##### JWTFilter #####");
        System.out.println("##### URL : "+ request.getRequestURL() +" #####");
        System.out.println("##### IP : "+ request.getRemoteAddr() +" #####");
        System.out.println("##### JWTFilter #####");

        // 헤더에서 access키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("authorization");

        // accessToken 인증이 필요 없는 요청 다음 필터로 넘김
        if(
                "/loginOauth".equals(request.getRequestURI()) || //테스트를 위한 임시 주소
                "/api/v1/login".equals(request.getRequestURI()) ||
                "/api/v1/signup".equals(request.getRequestURI()) ||
                "/api/v1/refresh".equals(request.getRequestURI()) ||
                "/api/v1/logout".equals(request.getRequestURI()) ||
                "/api/v1/reissue".equals(request.getRequestURI())
        ){
            // 다음 필터로 넘김
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            // 다음 필터로 넘김


            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // userId, role 값을 획득
        String userKey = jwtUtil.getUserKey(accessToken);



        UserEntity userEntity = userRepository.findByUserKey(userKey);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
