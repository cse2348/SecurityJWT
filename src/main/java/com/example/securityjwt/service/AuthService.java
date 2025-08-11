package com.example.securityjwt.service;

import com.example.securityjwt.dto.LoginRequest;
import com.example.securityjwt.dto.SignupRequest;
import com.example.securityjwt.dto.TokenResponse;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.jwt.JwtUtil;
import com.example.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 인증/토큰 발급 관련 비즈니스 로직 -> JWT의 subject는 username → userId 로 사용 , Access 토큰에는 role 클레임 포함(인가에 활용)
@Service  // Spring이 이 클래스를 서비스 계층으로 인식하고 Bean으로 등록
@RequiredArgsConstructor  // 필수 필드(final) 생성자 자동 생성 (DI 주입용)
public class AuthService {

    private final UserRepository userRepository;   // 사용자 정보를 DB에서 조회하는 Repository
    private final PasswordEncoder passwordEncoder; // 비밀번호 암호화/검증에 사용 (BCrypt)
    private final JwtUtil jwtUtil;                 // JWT 토큰 생성/검증 유틸 클래스

    // 회원가입 메서드
    // username 중복 체크 -> 비밀번호를 암호화한 후 새로운 User를 DB에 저장
    @Transactional
    public boolean signup(SignupRequest request) {
        final String username = request.getUsername();
        final String rawPassword = request.getPassword();

        // 이미 존재하는 사용자명인지 확인
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("이미 존재하는 사용자입니다.");
        }

        // 비밀번호 암호화 후 User 객체 생성 및 저장
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setRole("ROLE_USER"); // 기본 권한
        userRepository.save(user);

        return true;
    }

    // 로그인 메서드
    // username으로 User 조회 → 비밀번호 검증 → JWT Access / Refresh 발급 및 저장
    @Transactional
    public TokenResponse login(LoginRequest request) {
        final String username = request.getUsername();
        final String rawPassword = request.getPassword();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // 토큰 subject는 userId, Access에는 role 포함
        String accessToken  = jwtUtil.generateAccessToken(user.getId(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        // 발급한 RefreshToken을 DB에 저장 (재발급 시 검증용)
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // 리프레시 토큰으로 Access 토큰 재발급 -> 쿠키나 Authorization 헤더에서 꺼낸 원문을 그대로 넣어 호출
    @Transactional
    public TokenResponse refresh(String refreshTokenRaw) {
        // 방어코드: null/공백/길이 체크 + "Bearer " 접두사 제거
        String refreshToken = normalizeBearer(refreshTokenRaw);
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 유효성 검사 (서명/만료)
        if (!jwtUtil.validateToken(refreshToken) || !jwtUtil.isRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 토큰에서 사용자 식별자 추출 (subject=userId)
        Long userId;
        try {
            userId = jwtUtil.getUserIdFromToken(refreshToken);
        } catch (Exception e) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // DB의 저장 토큰과 일치 확인
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

        String storedRefresh = user.getRefreshToken();
        if (storedRefresh == null || !refreshToken.equals(storedRefresh)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 새로운 Access 토큰 발급 (role 포함)
        String newAccessToken = jwtUtil.generateAccessToken(user.getId(), user.getRole());

        // rotation 미사용: 기존 refreshToken 그대로 반환
        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // "Bearer xxx" 형태면 접두사를 제거하고, 양끝 공백을 정리 -> null 안전 처리 포함.
    private String normalizeBearer(String token) {
        if (token == null) return null;
        String t = token.trim();
        if (t.regionMatches(true, 0, "Bearer ", 0, 7)) { // 대소문자 무시하여 Bearer 인식
            t = t.substring(7);
        }
        return t.trim();
    }
}
