package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@RequiredArgsConstructor
@Controller
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String loginTest(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails) {

        System.out.println("/test/login ================");

        // authentication.getPrincipal() 은 Object Type 반환 -> PrincipalDetails 로 다운 캐스팅하여 PrincipalDetails 에 저장된 User 뽑아오기.
        // -> Authentication 을 다운캐스팅하여 User 객체를 얻어올 수 있다 ! (첫 번째 방법)

        // 또는 @AuthenticationPrincipal 어노테이션을 통해 미리 UserDetails 를 상속받는 타입으로 다운캐스팅한 PrincipalDetails 객체로
        // User 객체를 얻어올 수 있다 ! (두 번째 방법)

        System.out.println("api/test/login ================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        System.out.println("authentication = " + principalDetails.getAttributes());
        System.out.println("authentication = " + principalDetails.getUser());

        System.out.println(authentication.getPrincipal());

        System.out.println("userDetails : " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String loginTest(Authentication authentication,
                                          @AuthenticationPrincipal OAuth2User oAuth2User) {

        System.out.println("/test/oauth/login ================");
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        System.out.println("authentication = " + oauth2User.getAttributes());
        System.out.println("authentication = " + authentication.getPrincipal());

        System.out.println("oauth2User : " + oAuth2User.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    // 일반 로그인, OAuth 로그인 모두 분기할 필요없이 시큐리티 세션에서 저장된 User 객체를 가져올 수 있게된다.
    // 또한 @AuthenticationPrincipal 을 사용해 다운캐스팅할 필요없이 User 객체에 접근이 가능하다.
    // 원래 Principal ~ Service 객체를 만들지 않아도 알아서 로그인을 해주는데 굳이 만들어준 이유는 return PrincipalDetails 을 위해서 !
    // PrincipalOauth2UserService 는 묶는 이유 + OAuth2 에서 제공하는 데이터를 이용해 회원가입을 하기 위해서 !
    // 이렇게 통합된 return 을 통해 분기가 필요없어지는 것이다.
    @GetMapping("/user")
    public @ResponseBody
    String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails : " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    // Spring Security 를 사용하기 때문에 @PostMapping "/login" API 를 따로 만들지 않아도 된다.
    // 로그인을 위한 Form API 만 작성.
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    // Service 레이어 없이 간단하게 Controller 에서 로직 작성
    // 스프링 시큐리티의 암호는 암호화가 되어있어야 하므로 BCryptPasswordEncoder 를 통해 암호화 후 저장
    @PostMapping("/join")
    public String join(User user) {
        User saveUser = User.builder()
            .username(user.getUsername())
            .password(passwordEncoder.encode(user.getPassword()))
            .email(user.getEmail())
            .role("ROLE_USER")
            .build();

        userRepository.save(saveUser);

        return "redirect:/loginForm";
    }

    /*
        글로벌 Security 설정으로 권한에 따른 주소를 통제하지 않고, 간단하게 몇 개의 API 주소 호출을 권한에 따라 통제할 때는
        아래처럼 @Secured, @PreAuthorize 를 사용한다.
    * */

    // SecurityConfig 설정 클래스의 @EnableGlobalMethodSecurity 에 의해 @Secured 를 활성화
    // 아래처럼 간단하게 권한에 따른 주소 통제가 가능하다.
    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    // SecurityConfig 설정 클래스의 @EnableGlobalMethodSecurity 에 의해 @PreAuthorize, @PostAuthorize 를 활성화
    // @Secured 과 다르게 has~Role 문법을 사용해 여러 권한을 부여해 주소 통제가 가능하다.
    // @Pre~ 는 메소드 실행 전, @Post~ (잘 안씀) 는 메소드 실행 후 실행된다.
    @PreAuthorize("hasAnyRole('ROLE_MANAGER', 'ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터 정보";
    }
}
