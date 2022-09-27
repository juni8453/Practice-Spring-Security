package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

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

    // 함수 종료 시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // registrationId 로 어떤 OAuth 로 로그인 했는지 확인가능 (google)
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());
        System.out.println("getTokenValue : " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 구글로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> Code 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
        // userRequest 정보 -> loadUser 메소드를 통해 google 로부터 회원 프로필 받아내기
        // 즉, loadUser() 메소드의 역할은 OAuth 로부터 회원 프로필을 받아올 수 있는 역할을 담당한다.
        System.out.println("getAttributes : " + oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId; // 중복방지
        String email = oAuth2User.getAttribute("email");
        String password = bCryptPasswordEncoder.encode("password"); // 별 의미없는 패스워드
        String role = "ROLE_USER";

        User findUser = userRepository.findByUsername(username);

        if (findUser == null) {
            findUser = User.builder()
                .username(username)
                .password(password)
                .email(email)
                .role(role)
                .provider(provider)
                .providerId(providerId)
                .build();

            userRepository.save(findUser);
        }

        return new PrincipalDetails(findUser, oAuth2User.getAttributes());
    }
}
