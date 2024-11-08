package com.beanus.backend.contoller.user;

import com.beanus.backend.config.JwtConfig;
import com.beanus.backend.repository.user.RefreshRepository;
import com.beanus.backend.service.user.ReissueService;
import com.beanus.backend.util.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;

    private final RefreshRepository refreshRepository;

    private final JwtConfig jwtConfig;

    private final ReissueService reissueService;


    @PostMapping("/api/v1/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {



        //get refresh token
         String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refreshToken")) {
                //기존 쿠키에서 refreshToken 추출
                refresh = cookie.getValue();

                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }

        if (refresh == null) {

            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        //expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            //response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {

            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefreshToken(refresh);
        if (!isExist) {

            //response body
            return new ResponseEntity<>("exists refresh token", HttpStatus.BAD_REQUEST);
        }

        String userKey = jwtUtil.getUserKey(refresh);
        String role = jwtUtil.getRole(refresh);

        //make new JWT
        String accessToken = jwtUtil.createJwt("access",userKey, role, jwtConfig.getAccessExpiration());
        String refreshToken = jwtUtil.createJwt("refresh",userKey, role, jwtConfig.getRefreshExpiration());

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        reissueService.deleteRefreshToken(refresh);
        reissueService.saveRefreshToken(userKey,refreshToken, jwtConfig.getRefreshExpiration());


        //response
        response.setHeader("authorization", accessToken);
        response.setHeader("Set-Cookie", "JSESSIONID=; HttpOnly; SameSite=none; Secure");
        response.addCookie(jwtUtil.createCookie("refreshToken", refreshToken));
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

        return new ResponseEntity<>(HttpStatus.OK);
    }

}
