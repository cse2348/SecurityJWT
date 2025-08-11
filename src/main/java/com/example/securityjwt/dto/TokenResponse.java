package com.example.securityjwt.dto;

import lombok.*;

// 로그인/재발급 응답 DTO -> 쿠키 전략이라면 바디에 토큰을 포함하지 않아도 되지만, 테스트/문서화 편의를 위해 유지하는 경우가 많다고함
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenResponse {
    private String accessToken;
    private String refreshToken; // 쿠키만 쓸 땐 null로 내려도 무방
}
