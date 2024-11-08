package com.beanus.backend.contoller.user;

import com.beanus.backend.DTO.user.UserDTO;
import com.beanus.backend.service.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserService userService;

    @PostMapping("/api/v1/signup")
    public ResponseEntity<HttpStatus> signup(@RequestBody UserDTO userDTO) {
        userDTO.setName(userDTO.getNickname());
        UUID uuid = UUID.randomUUID();
        userDTO.setUserKey(uuid.toString());
        userService.save(userDTO); // 회원 가입 메서드 호출
        return ResponseEntity.ok().build(); // 회원 가입이 완료된 이후에 로그인 페이지로 이동
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        return new ResponseEntity<>(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }
}
