package com.example.securityjwt.dto;

import lombok.*;

// 로컬 로그인 요청 DTO : username/password 검증 → JWT 발급
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
// 소셜 로그인은 이 DTO를 사용하지 않음 -> OAuth2 인증을 통해 User 엔티티를 생성하고 JWT 발급
public class LoginRequest {
    private String username;
    private String password;
}
