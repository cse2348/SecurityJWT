package com.example.securityjwt.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

//로컬 로그인 & 소셜 로그인 모두 처리 가능
// Spring Security UserDetails 미구현 (수동 JWT 발급 방식이므로 불필요)

@Entity
@Table(name = "users") // MySQL 등에서 user 는 예약어라 안전하게 별도 테이블명 사용
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // Auto Increment
    private Long id;

    //  로컬 로그인용 필드
    @Column(unique = true, length = 50)
    // nullable 허용: 소셜 유저는 username이 없을 수 있음
    private String username;  // 사용자명 (로그인 ID)

    @JsonIgnore // 응답에 노출되지 않도록
    @Column(length = 60)
    // nullable 허용: 소셜 유저는 비밀번호가 없음
    private String password;  // 암호화된 비밀번호(BCrypt 해시 등)

    //소셜 로그인 필드
    @Column(length = 20)
    private String provider;   // GOOGLE / KAKAO / NAVER (로컬은 null)

    @Column(length = 100)
    private String providerId; // 소셜에서 제공하는 고유 사용자 ID

    // 공통 사용자 정보
    @Column(unique = true)
    private String email;      // 이메일 (소셜에서 없을 수 있음 → nullable)

    @Column(length = 50)
    private String name;       // 표시 이름

    @Column(length = 20)
    private String role = "ROLE_USER"; // 기본 권한

    @JsonIgnore
    @Column(length = 512)
    private String refreshToken;  // 리프레시 토큰 저장 (재발급 검증 시 사용)


}
