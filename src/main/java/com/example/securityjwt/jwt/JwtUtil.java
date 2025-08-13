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

/**
 * JWT 토큰 생성/파싱/검증 유틸
 * - Access: userId + role + tokenType=access
 * - Refresh: userId + tokenType=refresh
 */
@Component
public class JwtUtil {

    // 32자 이상(256bit) 권장
    @Value("${jwt.secret}")
    private String secretKey;

    private SecretKey key;

    // 유효기간
    private final long accessTokenValidity  = 60 * 60 * 1000L;            // 1시간
    private final long refreshTokenValidity = 14 * 24 * 60 * 60 * 1000L;  // 14일

    @PostConstruct
    public void init() {
        if (secretKey == null || secretKey.length() < 32) {
            throw new IllegalStateException("JWT 시크릿 키가 32자 미만입니다. (jwt.secret 확인)");
        }
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    // 내부 공통 생성기
    private String generateToken(String subjectUserId, long validityMs, String tokenType, String role) {
        var builder = Jwts.builder()
                .setSubject(subjectUserId)
                .claim("tokenType", tokenType)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + validityMs))
                .signWith(key, SignatureAlgorithm.HS256);

        if ("access".equals(tokenType) && role != null) {
            builder.claim("role", role);
        }
        return builder.compact();
    }

    /** Access Token 발급 (userId + role) */
    public String generateAccessToken(Long userId, String role) {
        return generateToken(String.valueOf(userId), accessTokenValidity, "access", role);
    }

    /** Refresh Token 발급 (userId만) */
    public String generateRefreshToken(Long userId) {
        return generateToken(String.valueOf(userId), refreshTokenValidity, "refresh", null);
    }

    /** (하위호환) username 기반 생성 — 가능하면 위 메서드 사용 권장 */
    @Deprecated
    public String generateToken(String username, long validityMs) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + validityMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ===== 파싱/검증 =====

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Long getUserIdFromToken(String token) {
        String sub = parseClaims(token).getSubject();
        return (sub == null) ? null : Long.valueOf(sub);
    }

    public String getUserRoleFromToken(String token) {
        return parseClaims(token).get("role", String.class);
    }

    public boolean isRefreshToken(String token) {
        try {
            return "refresh".equals(parseClaims(token).get("tokenType", String.class));
        } catch (Exception e) { return false; }
    }

    public boolean isAccessToken(String token) {
        try {
            return "access".equals(parseClaims(token).get("tokenType", String.class));
        } catch (Exception e) { return false; }
    }

    public Date getExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    /** 서명/만료/형식 검증 */
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (ExpiredJwtException | SignatureException | MalformedJwtException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}
