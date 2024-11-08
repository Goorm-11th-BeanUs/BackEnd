package com.beanus.backend.config.filter;

import com.beanus.backend.DTO.user.CustomUserDetails;
import com.beanus.backend.config.JwtConfig;
import com.beanus.backend.repository.user.RefreshRepository;
import com.beanus.backend.repository.user.UserRepository;
import com.beanus.backend.service.user.ReissueService;
import com.beanus.backend.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestBody;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;


public class LoginFilter extends UsernamePasswordAuthenticationFilter {



    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtUtil;

    private final RefreshRepository refreshRepository;

    private final UserRepository userRepository;

    private final JwtConfig jwtConfig;

    private final ReissueService reissueService;


    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository, UserRepository userRepository, JwtConfig jwtConfig, ReissueService reissueService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
        this.userRepository = userRepository;
        this.jwtConfig = jwtConfig;
        this.reissueService = reissueService;
        setFilterProcessesUrl("/api/v1/login");
    }
    @Override
    public Authentication attemptAuthentication(@RequestBody HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 보내진 email을 통해 userKey 조회
        String email = request.getParameter("email");
        String userKey = userRepository.findUserKeyByEmail(email);
        //request에서 password 추출
        String password = obtainPassword(request);

        //스프링 시큐리티에서 email과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userKey, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달

        Authentication authentication = authenticationManager.authenticate(authToken);

//        return authenticationManager.authenticate(authToken);
        return authentication;
    }


    @Override//로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        //UserDetailsS
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        String userKey = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();


        String accessToken = jwtUtil.createJwt("access",userKey, role, jwtConfig.getAccessExpiration());
        String refreshToken = jwtUtil.createJwt("refresh",userKey, role, jwtConfig.getRefreshExpiration());

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        reissueService.saveRefreshToken(userKey,refreshToken, jwtConfig.getRefreshExpiration());

        //헤더에 토큰을 담아서 클라이언트에게 전달
        response.setHeader("authorization", accessToken);
        response.setHeader("Set-Cookie", "JSESSIONID=; HttpOnly; SameSite=none; Secure");
        response.addCookie(jwtUtil.createCookie("refreshToken", refreshToken));
        response.setStatus(HttpStatus.OK.value());
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);
    }

}
