package com.beanus.backend.util;

import com.beanus.backend.DTO.user.CustomUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationUtil {

    public long getUserId(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        long userId = ((CustomUserDetails) authentication.getPrincipal()).getUserId();
        return userId;
    }
}
