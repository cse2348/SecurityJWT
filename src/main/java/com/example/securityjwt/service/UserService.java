package com.example.securityjwt.service;

import com.example.securityjwt.entity.User;
import com.example.securityjwt.repository.UserRepository;
import com.example.securityjwt.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service  // Spring이 이 클래스를 Service 계층으로 인식하고 Bean으로 등록
@RequiredArgsConstructor  // final 필드를 생성자 주입으로 자동 생성
public class UserService {

    private final UserRepository userRepository;  // 사용자 정보를 DB에서 조회하는 Repository

    // 사용자명(username)으로 User 정보를 조회하는 메서드
    // DB에서 username으로 사용자 정보를 찾고 반환 -> 사용자가 존재하지 않으면 UsernameNotFoundException 예외 발생
    @Transactional(readOnly = true) // 조회 트랜잭션 (성능/일관성)
    public User findByUsername(String username) {
        //return값 :  User 엔티티 (DB에 존재하는 사용자 정보)
        //@throws UsernameNotFoundException : 사용자를 찾을 수 없을 때 발생하는 예외
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    // 컨트롤러의 /auth/me 용도: SecurityContext의 Authentication에서 username 추출 → DTO로 반환
    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(Authentication authentication) {
        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return UserResponse.from(user); // DTO로 변환하여 응답
    }

    // (선택) 특정 username을 DTO로 바로 받고 싶을 때 사용할 수 있는 편의 메서드
    @Transactional(readOnly = true)
    public UserResponse findUserResponseByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return UserResponse.from(user);
    }
}
