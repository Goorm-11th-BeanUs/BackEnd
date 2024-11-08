package com.beanus.backend.service.user;

import com.beanus.backend.DTO.user.UserDTO;
import com.beanus.backend.domain.user.UserEntity;
import com.beanus.backend.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;

    public Long save(UserDTO dto){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return userRepository.save(UserEntity.builder()
                .email(dto.getEmail())
                .name(dto.getName())
                .userKey(dto.getUserKey())
                .password(encoder.encode(dto.getPassword()))
                .nickname(dto.getNickname())
                .build()).getId();
    }

    public UserEntity findById(Long userId){
        return userRepository.findById(userId)
                .orElseThrow(()-> new IllegalArgumentException("Unexpected User"));
    }

    public UserEntity findByEmail(String email){
        return userRepository.findByEmail(email)
                .orElseThrow(()-> new IllegalArgumentException("Unexpected User"));
    }

}
