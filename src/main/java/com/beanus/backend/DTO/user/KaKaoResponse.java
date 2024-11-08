package com.beanus.backend.DTO.user;

import java.util.Map;

public class KaKaoResponse implements OAuth2Response{

    private final Map<String, Object> attribute;
    private final String id;
    private final Map<String, Object> profile;

    public KaKaoResponse(Map<String, Object> attribute) {
        this.attribute = (Map<String, Object>) attribute.get("kakao_account");
        this.id = attribute.get("id").toString();
        this.profile = (Map<String, Object>) attribute.get("properties");
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getProviderId() {
        return this.id;
    }

    @Override
    public String getEmail() {
        return attribute.get("email").toString();
    }

    @Override
    public String getName() {

        return profile.get("nickname").toString();
    }

    public String getNickname(){
        return profile.get("nickname").toString();
    }
    public String getProfileImage(){
        return profile.get("profile_image").toString();
    }
}
