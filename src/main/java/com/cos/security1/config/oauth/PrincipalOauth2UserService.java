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
        // registrationId 로 어떤 OAuth 로 로그인 했는지 확인가능 (google)
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());

        System.out.println("getTokenValue : " + userRequest.getAccessToken().getTokenValue());

        // 구글로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> Code 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
        // userRequest 정보 -> loadUser 메소드를 통해 google 로부터 회원 프로필 받아내기
        // 즉, loadUser() 메소드의 역할은 OAuth 로부터 회원 프로필을 받아올 수 있는 역할을 담당한다.
        System.out.println("getAttributes : " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        return super.loadUser(userRequest);
    }
}
