package com.beanus.backend.service.user;

import com.beanus.backend.DTO.user.*;
import com.beanus.backend.domain.user.UserEntity;
import com.beanus.backend.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        System.out.println("registrationId : " + registrationId);

        OAuth2Response oAuth2Response = null;
        UserDTO userDTO = new UserDTO();
        if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
            userDTO.setNickname(((GoogleResponse) oAuth2Response).getNickname());
            userDTO.setProfileImage(((GoogleResponse) oAuth2Response).getProfileImage());
            userDTO.setName(oAuth2Response.getName());


        } else if (registrationId.equals("kakao")) {
            oAuth2Response = new KaKaoResponse(oAuth2User.getAttributes());
            userDTO.setNickname(((KaKaoResponse) oAuth2Response).getNickname());
            userDTO.setProfileImage(((KaKaoResponse) oAuth2Response).getProfileImage());

        }  else {
            return null;
        }

        userDTO.setEmail(oAuth2Response.getEmail());
        userDTO.setName(oAuth2Response.getName());
        userDTO.setRole("ROLE_USER");

        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 수 있는 Key 생성
        String userKey = oAuth2Response.getProvider() + "_" + oAuth2Response.getProviderId();
        userDTO.setUserKey(userKey);



        UserEntity existData = null;

        if(registrationId.equals("google")) {
            existData = userRepository.findByGoogleUserKey(userKey);
        }
        if(registrationId.equals("kakao")) {
            existData = userRepository.findByKakaoUserKey(userKey);
        }

        if(existData != null){ //한번도 가입하지 않은 유저인지 체크
            //oauth로 가입한 이력이 있는 유저
            existData.setEmail(userDTO.getEmail());
            existData.setName(userDTO.getName());
            existData.setNickname(userDTO.getNickname());
            existData.setProfileImage(userDTO.getProfileImage());
            existData.setRole(userDTO.getRole());
            if(registrationId.equals("google"))existData.setGoogleUserKey(userKey);
            if(registrationId.equals("kakao"))existData.setKakaoUserKey(userKey);

            userRepository.save(existData);

            return new CustomOAuth2User(userDTO);
        }
        else{ // 이미 가입한 유저일 경우 신규 정보로 업데이트

            //이메일로 이미 가입한 유저인지 판단
            if(userRepository.existsByEmail(userDTO.getEmail())){
                UserEntity userEntity = userService.findByEmail(userDTO.getEmail());
                userEntity.setProfileImage(userDTO.getProfileImage());
                userEntity.setNickname(userDTO.getNickname());
                userEntity.setName(userDTO.getName());
                userEntity.setRole(userDTO.getRole());
                if(registrationId.equals("google"))userEntity.setGoogleUserKey(userKey);
                if(registrationId.equals("kakao"))userEntity.setKakaoUserKey(userKey);
                userRepository.save(userEntity);
                return new CustomOAuth2User(userDTO);
            }else{
                //아무 가입도 진행하지 않은 유저
                UserEntity oauthUserEntity = new UserEntity();
                oauthUserEntity.setProfileImage(userDTO.getProfileImage());
                oauthUserEntity.setNickname(userDTO.getNickname());
                oauthUserEntity.setName(userDTO.getName());
                oauthUserEntity.setRole(userDTO.getRole());
                oauthUserEntity.setEmail(userDTO.getEmail());
                oauthUserEntity.setPassword("oauth-join");
                oauthUserEntity.setUserKey(userKey);
                if(registrationId.equals("google"))oauthUserEntity.setGoogleUserKey(userKey);
                if(registrationId.equals("kakao"))oauthUserEntity.setKakaoUserKey(userKey);
                userRepository.save(oauthUserEntity);
                return new CustomOAuth2User(userDTO);
            }

        }
    }
}