package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/*
    시큐리티 설정에서 loginProcessingUrl("/login") 을 걸어뒀기 때문에 /login 요청이 오면,
    자동으로 UserDetailsService Type 으로 IoC 되어 있는 PrincipalDetailsService 의 loadUserByUsername() 메소드가 실행된다. (규칙)
*/
@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 인자로 받는 username 과 넘어오는 parameter 이름을 맞춰서 매칭시켜줘야 한다.
    // input type ~ name="username" 으로 넘기기 때문에 username 으로 맞춰주자.

    // 리턴된 값은 Authentication(내부 UserDetails) 에 들어가게 된다.
    // 이후 시큐리티 Session(내부 Authentication(내부 UserDetails)) 로 들어가게 된다.
    // 즉, loadUserByUsername() 메소드가 실행되면서 시큐리티 Session 내부가 셋팅되게 된다.
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        User findUser = Optional.of(user)
            .orElseThrow(() -> new UsernameNotFoundException("계정을 찾을 수 없습니다."));

        return new PrincipalDetails(findUser);
    }
}
