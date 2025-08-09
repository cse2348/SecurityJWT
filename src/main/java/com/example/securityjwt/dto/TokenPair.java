package com.example.securityjwt.dto;

import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class TokenPair {
    private String tokenType;       // "Bearer"
    private String accessToken;
    private long   accessTokenExpiresAt;  // epoch millis
    private String refreshToken;
    private long   refreshTokenExpiresAt; // epoch millis
}

