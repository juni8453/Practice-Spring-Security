package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig) 가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        // 스프링 시큐리티가 켜져있으면 자동으로 CSRF Token 을 검증한다.
        // disable() 을 해줘야 포스트맨에 따로 CSRF Token 을 검증할 필요가 없어지기 때문에 disable() 해준 것!
        httpSecurity.csrf().disable();
        httpSecurity.authorizeRequests()

            // 1. authenticated() -> 인증이 필요하다.
            .antMatchers("/user/**").authenticated()

            // 2. access() -> 인증 뿐 아니라 hasAnyRole(~) ~ 권한이 있는 사람만 접속할 수 있다.
            .antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER', 'ROLE_ADMIN')")
            .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")

            // 3. 위의 주소가 아니면 모두 접속 허용
            .anyRequest().permitAll()

            // 4. form 로그인 기반인 경우
            // 권한이 없는 페이지에 접속한다면 loginPage() 에 의해 "/loginForm" 으로 이동
            .and().formLogin().loginPage("/loginForm")

            // 4-1. /login 주소가 호출이 되면, 시큐리티가 낚아채서 대신 로그인을 진행해준다.
            //  즉, controller 에 /login 을 만들지 않아도 된다.
            //  로그인이 완료되면 "/" 홈페이지로 이동하도록 설정
            //  로그인이 실패하면 "/loginForm" 으로 이동하도록 설정
            .loginProcessingUrl("/login")
            .defaultSuccessUrl("/")
            .failureUrl("/loginForm")

            // 6. oauth 로그인 기반인 경우
            // 권한이 없는 페이지에 접속한다면 loginPage() 에 의해 "/loginForm" 으로 이동
            .and().oauth2Login().loginPage("/loginForm")
            .defaultSuccessUrl("/")
            .failureUrl("/loginForm")
            .userInfoEndpoint()
            .userService(principalOauth2UserService);
        ;

        return httpSecurity.build();
    }
}
