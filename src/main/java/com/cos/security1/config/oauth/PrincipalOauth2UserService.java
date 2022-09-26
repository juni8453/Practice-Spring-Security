package com.cos.security1.config.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    // Form 로그인이 아닌, OAuth 로그인 시도할 때 호출되어 후처리하는 함수
    // 구글로 부터 받은 userRequest 데이터를 후처리한다.

    /*
        username = "google_112464088282265915760(getAttributes 의 sub 값)
        password = "암호화 된 비밀번호 아무거나"
        email = "jbj9710@gmail.com"
        role = "ROLE_USER"
        provider = "google"
        providerId = 112464088282265915760(역시 sub 값)

        -> 이 정보를 토대로 회원가입 진행할 예정
    * */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());
        System.out.println("getTokenValue : " + userRequest.getAccessToken().getTokenValue());
        System.out.println("getAttributes : " + super.loadUser(userRequest).getAttributes());
        return super.loadUser(userRequest);
    }
}
