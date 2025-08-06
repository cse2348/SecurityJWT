package com.example.securityjwt.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    private String secretKey = "MySuperSecretKeyThatIsAtLeast32CharsLong!!";  // 32글자 이상 비밀키 설정
    private SecretKey key;  // 서명에 사용할 SecretKey 객체

    private final long accessTokenValidity = 60 * 60 * 1000L; // 1시간
    private final long refreshTokenValidity = 14 * 24 * 60 * 60 * 1000L; // 14일

    @PostConstruct
    public void init() {
        // SecretKey를 Base64 인코딩 후 Key 객체로 변환하여 서명에 사용할 수 있도록 초기화
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
        key = Keys.hmacShaKeyFor(encodedKey.getBytes());
    }

    //JWT를 발급하는 메서드
    public String generateToken(String username, long validity) {
        //@return값 :  JWT 문자열
        return Jwts.builder()
                .setSubject(username)  // payload에 subject로 username 저장
                .setIssuedAt(new Date())  // 토큰이 발급된 시각 (issuedAt)
                .setExpiration(new Date(System.currentTimeMillis() + validity))  // 만료 시각 설정 (현재 시간 + 유효기간)
                // validity : 토큰의 유효기간 (AccessToken / RefreshToken을 구분해서 사용)
                .signWith(key, SignatureAlgorithm.HS256)  // 서명 알고리즘 및 SecretKey로 서명
                .compact();  // JWT 문자열로 직렬화해서 반환 (최종 완성된 토큰 문자열)
    }

    //Access Token을 발급하는 메서드
    public String generateAccessToken(String username) {
        //@return값: Access Token 문자열
        return generateToken(username, accessTokenValidity);
    }

    //Refresh Token을 발급하는 메서드
    public String generateRefreshToken(String username) {
        // @return값 :  Refresh Token 문자열
        return generateToken(username, refreshTokenValidity);
    }

    // JWT에서 사용자명을 추출하는 메서드
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)  // 토큰을 서명할 때 사용했던 SecretKey로 검증
                .build()
                .parseClaimsJws(token)  // 토큰을 파싱해서 payload(body)를 꺼냄 (서명이 올바르지 않으면 여기서 예외 발생)
                .getBody()  // payload(body)에 접근
                .getSubject();  // subject(username)를 꺼냄
    }

    // 토큰이 유효한지 검증하는 메서드
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)  // 토큰을 서명할 때 사용했던 SecretKey로 검증
                    .build()
                    .parseClaimsJws(token);  // 토큰 파싱 (서명 검증 및 만료시간 체크를 자동으로)
            return true;  // 에러가 발생하지 않으면 유효한 토큰
        } catch (Exception e) {
            return false;  // 서명이 잘못되었거나, 만료되었으면 false 반환
        }
    }
}
