package com.example.securityjwt.Service;

import com.example.securityjwt.Entity.User;
import com.example.securityjwt.Repository.UserRepository;
import com.example.securityjwt.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service  // Spring이 이 클래스를 서비스 계층으로 인식하고 Bean으로 등록
@RequiredArgsConstructor  // 필수 필드(final) 생성자 자동 생성 (DI 주입용)
public class AuthService {

    private final UserRepository userRepository;  // 사용자 정보를 DB에서 조회하는 Repository
    private final PasswordEncoder passwordEncoder;  // 비밀번호 암호화/검증에 사용 (BCrypt)
    private final JwtUtil jwtUtil;  // JWT 토큰 생성/검증 유틸 클래스

    // 회원가입 메서드
    // username 중복 체크 -> 비밀번호를 암호화한 후 새로운 User를 DB에 저장
    public void signup(String username, String password) {
        // 이미 존재하는 사용자명인지 확인
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("이미 존재하는 사용자입니다.");
        }

        // 비밀번호 암호화 후 User 객체 생성 및 저장
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }

    // 로그인 메서드
    // username으로 User 정보를 조회하고 비밀번호 일치 여부를 확인 - > 인증 성공 시 JWT Access Token을 발급하여 반환
    public String login(String username, String password) {
        // 사용자명으로 User 조회 (없으면 예외 발생)
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

        // 비밀번호 일치 여부 검증
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // 인증 성공시 JWT Access Token 발급
        return jwtUtil.generateAccessToken(username);
    }

    // 리프레시 토큰을 이용한 Access Token 재발급 메서드
    // 리프레시 토큰 유효성 검증 만약 유효한 경우 username을 추출하여 새로운 Access Token 발급
    public String refresh(String refreshToken) {
        // 리프레시 토큰 유효성 검증
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 토큰에서 사용자명 추출
        String username = jwtUtil.getUsernameFromToken(refreshToken);

        // 새로운 Access Token 발급 후 반환
        return jwtUtil.generateAccessToken(username);
    }

    // 리프레시 토큰 발급 메서드
    // username을 받아서 새로운 Refresh Token을 생성하여 반환
    public String generateRefreshToken(String username) {
        return jwtUtil.generateRefreshToken(username);
    }
}
