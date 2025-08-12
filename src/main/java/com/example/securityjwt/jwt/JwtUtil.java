package com.example.securityjwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct; // Boot 3: jakarta 사용
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// JWT 토큰 생성/파싱/검증 유틸
// - Access Token: userId + role (인가용)
// - Refresh Token: userId만 포함 (재발급용)
@Component
public class JwtUtil {
    // GitHub Secrets에서 주입받아 사용
    @Value("${jwt.secret}")
    private String secretKey;  // 32글자 이상 비밀키 설정 (HS256 최소 256bit 권장)

    private SecretKey key;     // 서명에 사용할 SecretKey 객체

    // 유효기간 (필요시 application.yml로 옮겨도 됨)
    private final long accessTokenValidity  = 60 * 60 * 1000L;             // 1시간
    private final long refreshTokenValidity = 14 * 24 * 60 * 60 * 1000L;   // 14일

    @PostConstruct
    public void init() {
        // SecretKey를 HMAC-SHA용 Key 객체로 변환하여 서명에 사용할 수 있도록 초기화
        if (secretKey == null || secretKey.length() < 32) {
            // HS256은 최소 256bit(32바이트) 권장
            throw new IllegalStateException("JWT 시크릿 키 길이가 32자 미만입니다. (환경변수 jwt.secret 확인)");
        }
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }


    // 토큰 타입을 명시하여 생성하는 내부 메서드
    // subject: userId(String)
     // tokenType: "access" | "refresh"
     // role: Access 토큰일 때만 세팅, Refresh는 null
    private String generateToken(String subjectUserId, long validity, String tokenType, String role) {
        var builder = Jwts.builder()
                .setSubject(subjectUserId)                       // payload subject에 userId 저장
                .claim("tokenType", tokenType)                  // access/refresh 구분 클레임
                .setIssuedAt(new Date())                        // 토큰 발급 시각
                .setExpiration(new Date(System.currentTimeMillis() + validity))  // 만료 시각
                .signWith(key, SignatureAlgorithm.HS256);       // HS256 서명

        if ("access".equals(tokenType) && role != null) {
            builder.claim("role", role);                        // 인가용 권한 정보
        }
        return builder.compact();                               // JWT 문자열 반환
    }

    // Access Token을 발급하는 메서드 (userId + role 포함)
    public String generateAccessToken(Long userId, String role) {
        // @return값: Access Token 문자열
        return generateToken(String.valueOf(userId), accessTokenValidity, "access", role);
    }

    // Refresh Token을 발급하는 메서드 (userId만 포함)
    public String generateRefreshToken(Long userId) {
        // @return값 : Refresh Token 문자열
        return generateToken(String.valueOf(userId), refreshTokenValidity, "refresh", null);
    }

    // (하위호환) username 기반 생성 — 기존 코드 호환용 (가능하면 위 메서드들을 사용)
    @Deprecated
    public String generateToken(String username, long validity) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + validity))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // 파싱/검증 유틸
    // 공통: Claims 파싱 (서명/만료 검증 포함). 예외는 호출부에서 처리하거나 validateToken으로 선검증 권장.
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)  // 토큰을 서명할 때 사용했던 SecretKey로 검증
                .build()
                .parseClaimsJws(token) // 토큰 파싱 + 서명/만료 검증
                .getBody();            // payload(body) 반환
    }

    // JWT에서 userId(subject)를 추출하는 메서드
    public Long getUserIdFromToken(String token) {
        String sub = parseClaims(token).getSubject();  // subject(userId 문자열)
        return (sub == null) ? null : Long.valueOf(sub);
    }

    // JWT에서 role을 추출 (Access 토큰에만 존재)
    public String getUserRoleFromToken(String token) {
        return parseClaims(token).get("role", String.class);
    }

    // 토큰 타입이 refresh인지 검사 (토큰 타입 클레임 기반)
    public boolean isRefreshToken(String token) {
        try {
            Claims c = parseClaims(token);
            String type = c.get("tokenType", String.class);
            return "refresh".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰 타입이 access인지 검사
    public boolean isAccessToken(String token) {
        try {
            Claims c = parseClaims(token);
            String type = c.get("tokenType", String.class);
            return "access".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰 만료시각 반환 (필요 시 사용)
    public Date getExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    // 토큰이 유효한지 검증하는 메서드 (서명/만료/형식)
    public boolean validateToken(String token) {
        try {
            // 토큰 파싱 (서명 검증 및 만료시간 체크 자동 수행)
            parseClaims(token);
            return true;  // 에러가 발생하지 않으면 유효한 토큰
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            // 만료
            return false;
        } catch (io.jsonwebtoken.security.SignatureException e) {
            // 서명 불일치(비밀키 불일치)
            return false;
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            // 형식 오류
            return false;
        } catch (Exception e) {
            // 기타 오류
            return false;
        }
    }
}
