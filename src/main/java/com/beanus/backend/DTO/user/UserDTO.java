package com.beanus.backend.DTO.user;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {

    private long id;
    private String role;
    private String userKey;
    private String email;
    private String profileImage;
    private String name;
    private String nickname;
    private String password;

}
