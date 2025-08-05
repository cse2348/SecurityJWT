package com.example.securityjwt.Service;

import com.example.securityjwt.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service  // Spring이 이 클래스를 Service 계층으로 인식하고 Bean으로 등록
@RequiredArgsConstructor  // 생성자 주입 (final 필드를 자동으로 생성자 주입)
public class UserDetailsServiceImpl implements UserDetailsService {
    //UserDetailsService -> Spring Security에서 사용자 인증을 담당하는 핵심 인터페이스
    //loadUserByUsername -> Security가 로그인 시 자동으로 호출하는 메서드
    private final UserRepository userRepository;  // DB에서 사용자 정보를 조회하는 Repository (JPA)

    /*
     Spring Security가 로그인 시 호출하는 메서드
     username (ID)로 사용자 정보를 조회하여 반환 -> UserDetails를 반환해야 Spring Security가 인증 처리를 할 수 있음
     UserDetails ->Spring Security가 이해할 수 있는 사용자 정보 객체
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // username으로 User를 조회하고 없으면 예외 발생
        // @throws UsernameNotFoundException 사용자를 찾지 못했을 때 발생시키는 예외
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }
}
