package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig) 가 스프링 필터체인에 등록이 된다.
public class SecurityConfig {

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

            // 4. 권한이 없는 페이지 접속 후 login 페이지로 이동하기 위해선 ?
            .and().formLogin().loginPage("/login");

        return httpSecurity.build();
    }
}
