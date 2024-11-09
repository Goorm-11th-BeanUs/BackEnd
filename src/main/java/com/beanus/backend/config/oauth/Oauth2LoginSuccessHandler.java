package com.beanus.backend.config.oauth;

import com.beanus.backend.DTO.user.UserDTO;
import com.beanus.backend.config.JwtConfig;
import com.beanus.backend.domain.user.UserEntity;
import com.beanus.backend.repository.user.RefreshRepository;
import com.beanus.backend.repository.user.UserRepository;
import com.beanus.backend.service.user.ReissueService;
import com.beanus.backend.util.JWTUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class Oauth2LoginSuccessHandler  extends SimpleUrlAuthenticationSuccessHandler {
    private final JWTUtil jwtUtil;

    private final RefreshRepository refreshRepository;

    private final ObjectMapper objectMapper;

    private final UserRepository userRepository;

    private final JwtConfig jwtConfig;

    private final ReissueService reissueService;

    //Oauth2를 통한 로그인 성공시 Success 처리
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //UserDetailsS

        UserDTO customUserDetails = objectMapper.convertValue(authentication.getPrincipal(), UserDTO.class);
        String userKey = customUserDetails.getUserKey();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        //해당하는 type의 oauth를 찾아 유저 정보를 조회
        UserEntity userEntity = null;
        if(request.getRequestURL().toString().contains("google")){
            userEntity = userRepository.findByGoogleUserKey(userKey);
        }else if(request.getRequestURL().toString().contains("kakao")){
            userEntity = userRepository.findByKakaoUserKey(userKey);
        }else{
            throw new IllegalArgumentException("Invalid oauth type");
        }





        // 600000L = 10분
        String accessToken = jwtUtil.createJwt("access",userEntity.getUserKey(), role, jwtConfig.getAccessExpiration());
        String refreshToken = jwtUtil.createJwt("refresh",userEntity.getUserKey(), role, jwtConfig.getRefreshExpiration());

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        reissueService.saveRefreshToken(userKey,refreshToken, jwtConfig.getRefreshExpiration());

        //헤더에 토큰을 담아서 클라이언트에게 전달
        response.setHeader("authorization", accessToken);
        response.setHeader("Set-Cookie", "JSESSIONID=; HttpOnly; SameSite=none; Secure");
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);
        response.addCookie(jwtUtil.createCookie("refreshToken", refreshToken));
        response.sendRedirect("http://localhost:5173/oauth2/redirect");
        response.setStatus(HttpStatus.OK.value());
    }

}
