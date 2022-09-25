package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@RequiredArgsConstructor
@Controller
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user() {
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
