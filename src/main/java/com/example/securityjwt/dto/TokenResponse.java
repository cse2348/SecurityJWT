package com.example.securityjwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.io.Serializable;

/**
 * 로그인/재발급 응답 DTO
 * - accessToken, refreshToken 한 쌍으로 반환할 때 사용합니다.
 * - refreshToken 없이 accessToken만 내려줄 경우엔 필드를 null로 둘 수도 있습니다.
 */
@Getter
@AllArgsConstructor
@Builder
public class TokenResponse implements Serializable {

    /** API 호출 때 Authorization: Bearer {accessToken} 로 사용 */
    private final String accessToken;

    /** accessToken 갱신 용도. 보안상 httpOnly 쿠키에 저장하거나 서버에 해시로 보관하는 방식을 권장 */
    private final String refreshToken;

    /** (옵션) 토큰 타입을 명시하고 싶을 경우 사용 (기본 Bearer) */
    @Builder.Default
    private final String tokenType = "Bearer";

    /** (옵션) accessToken 만료(초) - 클라이언트 UX 개선용 메타데이터 */
    private final Long expiresIn;
}
