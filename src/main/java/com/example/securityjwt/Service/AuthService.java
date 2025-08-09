package com.example.securityjwt.Service;

import com.example.securityjwt.Entity.User;
import com.example.securityjwt.Repository.UserRepository;
import com.example.securityjwt.dto.AuthResponse;
import com.example.securityjwt.dto.LoginRequest;
import com.example.securityjwt.dto.SignupRequest;
import com.example.securityjwt.dto.TokenPair;
import com.example.securityjwt.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
        userRepository.save(user);

        return true;
    }

    // 로그인 메서드
    // username으로 User 정보를 조회하고 비밀번호 일치 여부를 확인 -> 인증 성공 시 JWT Access Token & Refresh Token 발급 및 저장
    @Transactional
    public AuthResponse login(LoginRequest request) {
        final String username = request.getUsername();
        final String rawPassword = request.getPassword();

        // 사용자명으로 User 조회 (없으면 예외 발생)
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

        // 비밀번호 일치 여부 검증
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // 인증 성공 시 AccessToken, RefreshToken 발급
        String accessToken = jwtUtil.generateAccessToken(username);
        String refreshToken = jwtUtil.generateRefreshToken(username);

        // 발급한 RefreshToken을 DB에 저장
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        // AccessToken, RefreshToken을 DTO 형태로 반환 (만료 시각은 필요 시 JwtUtil에서 파싱하여 채워도 됨)
        TokenPair tokens = TokenPair.builder()
                .tokenType("Bearer")
                .accessToken(accessToken)
                .accessTokenExpiresAt(0L)   // 필요 시 JwtUtil에서 exp 파싱하여 채우세요
                .refreshToken(refreshToken)
                .refreshTokenExpiresAt(0L)  // 필요 시 JwtUtil에서 exp 파싱하여 채우세요
                .build();

        return AuthResponse.builder()
                .tokens(tokens)
                .build();
    }

    // 리프레시 토큰을 이용한 Access Token 재발급 메서드
    // DB에 저장된 리프레시 토큰과 비교하여 일치하는 경우에만 Access Token 발급
    @Transactional
    public AuthResponse refresh(String refreshTokenRaw) {
        // 0) 방어코드: null/공백/길이 체크 + "Bearer " 접두사 제거
        String refreshToken = normalizeBearer(refreshTokenRaw);
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 1) 리프레시 토큰 유효성 검증 (서명 & 유효기간)
        //    JwtUtil.validateToken은 모든 예외(만료/서명/형식)를 false로 반환
        if (!jwtUtil.validateToken(refreshToken)) {
            // NOTE: 만료/서명/형식 불일치 등 모든 케이스 동일 메시지로 응답
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 1-1) 토큰 타입이 'refresh' 인지 추가 확인(액세스를 실수로 보낸 케이스 차단)
        if (!jwtUtil.isRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 2) 토큰에서 사용자명 추출 (파싱 실패 시도 동일 메시지)
        String username;
        try {
            username = jwtUtil.getUsernameFromToken(refreshToken);
        } catch (Exception e) {
            // 토큰 파싱 실패 (형식/서명/만료 등) → 동일 메시지
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 3) DB에서 사용자 조회 및 저장된 리프레시 토큰과 비교
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

        String storedRefresh = user.getRefreshToken();
        // 저장된 토큰과 정확히 일치해야 함 (회전 사용 시 여기서 로직 변경)
        if (storedRefresh == null || !refreshToken.equals(storedRefresh)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // 4) 새로운 Access Token 발급
        String newAccessToken = jwtUtil.generateAccessToken(username);

        // (선택) Refresh Token Rotation을 원한다면 여기서 새 Refresh Token 발급 및 교체 저장
        // String newRefreshToken = jwtUtil.generateRefreshToken(username);
        // user.setRefreshToken(newRefreshToken);
        // userRepository.save(user);

        TokenPair tokens = TokenPair.builder()
                .tokenType("Bearer")
                .accessToken(newAccessToken)
                .accessTokenExpiresAt(0L)   // 필요 시 exp로 채우세요
                .refreshToken(refreshToken) // rotation 안 했으므로 기존 값 반환
                .refreshTokenExpiresAt(0L)  // 필요 시 exp로 채우세요
                .build();

        return AuthResponse.builder()
                .tokens(tokens)
                .build();
    }

    // --- 내부 유틸 ---

    /**
     * "Bearer xxx" 형태면 접두사를 제거하고, 양끝 공백을 정리한다.
     * null 안전 처리 포함.
     */
    private String normalizeBearer(String token) {
        if (token == null) return null;
        String t = token.trim();
        if (t.regionMatches(true, 0, "Bearer ", 0, 7)) { // 대소문자 무시하여 Bearer 인식
            t = t.substring(7);
        }
        return t.trim();
    }
}
