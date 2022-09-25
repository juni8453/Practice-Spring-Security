package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

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
    public@ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    // 시큐리티가 해당 주소를 낚아챈다.
    // SecurityConfig 파일 생성 후 낚아채지 않는다.
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
}
