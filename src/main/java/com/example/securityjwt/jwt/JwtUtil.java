package com.example.securityjwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// JWT 생성, 파싱, 검증을 담당하는 유틸리티 클래스
@Component
public class JwtUtil {

    // 환경변수에서 주입 (32자 이상 권장)
    @Value("${jwt.secret}")
    private String secretKey;

    // HMAC SHA-256 서명에 사용될 키 객체
    private SecretKey key;

    // 토큰 유효기간 설정
    private final long accessTokenValidity  = 60 * 60 * 1000L;            // AccessToken: 1시간
    private final long refreshTokenValidity = 14 * 24 * 60 * 60 * 1000L;  // RefreshToken: 14일

    // 초기화 시점에 secretKey를 기반으로 HMAC SHA-256 SecretKey 생성
    @PostConstruct
    public void init() {
        if (secretKey == null || secretKey.length() < 32) {
            throw new IllegalStateException("JWT 시크릿 키가 32자 미만입니다. (jwt.secret 확인)");
        }
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    // 내부 공통 토큰 생성 메서드
    private String generateToken(String subjectUserId, long validityMs, String tokenType, String role) {
        var builder = Jwts.builder()
                .setSubject(subjectUserId)                         // sub 클레임: 사용자 ID
                .claim("tokenType", tokenType)                     // 커스텀 클레임: 토큰 타입
                .setIssuedAt(new Date())                           // iat: 발급 시각
                .setExpiration(new Date(System.currentTimeMillis() + validityMs)) // exp: 만료 시각
                .signWith(key, SignatureAlgorithm.HS256);          // 서명 (HMAC SHA-256)

        // AccessToken인 경우만 role 포함
        if ("access".equals(tokenType) && role != null) {
            builder.claim("role", role);
        }
        return builder.compact();
    }

    //  Access Token 발급 (사용자 ID + 권한 포함)
    public String generateAccessToken(Long userId, String role) {
        return generateToken(String.valueOf(userId), accessTokenValidity, "access", role);
    }

    // Refresh Token 발급 (사용자 ID만 포함)
    public String generateRefreshToken(Long userId) {
        return generateToken(String.valueOf(userId), refreshTokenValidity, "refresh", null);
    }

    // (하위 호환) username 기반 토큰 발급 -> @deprecated userId 기반 메서드 사용
    @Deprecated
    public String generateToken(String username, long validityMs) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + validityMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰 파싱과 클레임 조회
    // JWT를 파싱하여 Claims(페이로드) 반환
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)   // 서명 검증에 사용할 키
                .build()
                .parseClaimsJws(token) // JWS(JSON Web Signature) 파싱
                .getBody();
    }

    // 토큰에서 사용자 ID(sub) 추출
    public Long getUserIdFromToken(String token) {
        String sub = parseClaims(token).getSubject();
        return (sub == null) ? null : Long.valueOf(sub);
    }

    //토큰에서 role 클레임 추출
    public String getUserRoleFromToken(String token) {
        return parseClaims(token).get("role", String.class);
    }

    // Refresh Token 여부 확인
    public boolean isRefreshToken(String token) {
        try {
            return "refresh".equals(parseClaims(token).get("tokenType", String.class));
        } catch (Exception e) {
            return false;
        }
    }

    // Access Token 여부 확인
    public boolean isAccessToken(String token) {
        try {
            return "access".equals(parseClaims(token).get("tokenType", String.class));
        } catch (Exception e) {
            return false;
        }
    }

    //  토큰 만료 시각 반환
    public Date getExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    //  토큰 유효성 검증 (서명, 만료, 포맷)
    public boolean validateToken(String token) {
        try {
            parseClaims(token); // 파싱 성공 시 유효
            return true;
        } catch (ExpiredJwtException | SignatureException | MalformedJwtException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}
