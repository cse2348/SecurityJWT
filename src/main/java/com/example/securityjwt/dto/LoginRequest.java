package com.example.securityjwt.dto;

import lombok.*;

// 로컬 로그인 요청 DTO : username/password 검증 → JWT 발급
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequest {
    private String username;
    private String password;
}
