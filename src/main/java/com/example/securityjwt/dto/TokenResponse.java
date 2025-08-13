package com.example.securityjwt.dto;

import lombok.*;

// 로그인/재발급 응답 DTO
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
}
