package com.example.securityjwt.dto;

import lombok.*;

// 로그인/재발급 응답 DTO -> 쿠키 전략이라면 바디에 토큰을 포함하지 않아도 됌
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
}
