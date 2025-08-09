package com.example.securityjwt.dto;

import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class AuthResponse {
    private TokenPair tokens;

    // 필요시 사용자 요약을 같이 내려줄 수 있음
    // private UserResponse user;
}