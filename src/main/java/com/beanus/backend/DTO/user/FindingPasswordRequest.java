package com.beanus.backend.DTO.user;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class FindingPasswordRequest {
    private String email;
    private String authCode;
    private String password;
}
