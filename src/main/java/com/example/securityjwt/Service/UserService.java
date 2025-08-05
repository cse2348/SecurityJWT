package com.example.securityjwt.Service;

import com.example.securityjwt.Entity.User;
import com.example.securityjwt.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service  // Spring이 이 클래스를 Service 계층으로 인식하고 Bean으로 등록
@RequiredArgsConstructor  // final 필드를 생성자 주입으로 자동 생성
public class UserService {

    private final UserRepository userRepository;  // 사용자 정보를 DB에서 조회하는 Repository

    /*
    사용자명(username)으로 User 정보를 조회하는 메서드
    DB에서 username으로 사용자 정보를 찾고 반환 -> 사용자가 존재하지 않으면 UsernameNotFoundException 예외 발생
     */
    public User findByUsername(String username) {
        //return값 :  User 엔티티 (DB에 존재하는 사용자 정보)
        //@throws UsernameNotFoundException : 사용자를 찾을 수 없을 때 발생하는 예외
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
