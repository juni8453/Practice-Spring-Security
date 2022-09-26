package com.cos.security1.config.auth;

// 시큐리티가 /login 주소 요청을 낚아채서 로그인을 진행시킨다.
// 로그인 진행이 완료가 되면 시큐리티 자신만의 session 을 만들어준다. (Key : Security ContextHolder)
// 시큐리티가 가지고 있는 세션에 들어갈 수 있는 객체는 정해져있다. -> Authentication Type 객체
// Authentication Type 객체 안에 User 정보가 있어야 하는데, User Type 은 UserDetails Type 객체이다.

// 정리하자면, 시큐리티가 가지고 있는 세션 영역이 있고, 여기 들어갈 수 있는 객체 Type 은 Authentication Type 이고 이 안에 User 정보를 저장한다.
// User 정보에 들어갈 수 있는 객체는 UserDetails Type !
// Security Session -> Authentication -> UserDetails(PrincipalDetails)

import lombok.RequiredArgsConstructor;

import com.cos.security1.model.User;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails {

    private final User user;

    // 1. 유저의 권한을 리턴하는 메소드
    // 현재 User 의 권한은 String Type 이므로 List<GrantedAuthority> Type 으로 바꿔서 리턴해주면 된다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> auths = new ArrayList<>();
        auths.add((GrantedAuthority) user::getRole);

        return auths;
    }

    // 2. 유저의 패스워드를 리턴하는 메소드
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    // 3. 유저의 아이디를 리턴하는 메소드
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 4. 계정 만료를 체크하는 메소드
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 5. 계정 잠금을 체크하는 메소드
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 6. 계정 비밀번호의 만료기간을 체크하는 메소드
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 7. 계정 활성화를 체크하는 메소드
    @Override
    public boolean isEnabled() {

        /*
            예시)
            우리 사이트에서 1년동안 로그인을 하지 않는 계정을 휴먼 계정으로 바꾼다고 가정.
            현재 시간 - 로그인 시간 = 1년 초과했을 때 return false;
        */

        return true;
    }
}
