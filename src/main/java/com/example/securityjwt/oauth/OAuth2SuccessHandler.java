package com.example.securityjwt.oauth;

import com.example.securityjwt.entity.User;
import com.example.securityjwt.jwt.JwtUtil;
import com.example.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws IOException {
        // 인증 객체에서 OAuth2AuthenticationToken 추출
        OAuth2AuthenticationToken oauth = (OAuth2AuthenticationToken) auth;
        String provider = oauth.getAuthorizedClientRegistrationId().toLowerCase(Locale.ROOT);

        // OAuth2User에서 사용자 속성(Map) 추출
        OAuth2User principal = (OAuth2User) oauth.getPrincipal();
        Map<String, Object> attrs = principal.getAttributes();
        String providerId = extractProviderId(provider, attrs); // google: sub / kakao: id / naver: response.id

        // 최초 로그인은 CustomOAuth2UserService에서 가입 처리됨 → 여기서는 DB 조회
        User user = userRepository.findByProviderAndProviderId(provider, providerId)
                .orElseThrow(() -> new IllegalStateException("OAuth user not found after signup"));

        Long userId = user.getId();
        String role = (user.getRole() != null && !user.getRole().isBlank()) ? user.getRole() : "ROLE_USER";

        // JWT 생성 (userId + role 기반)
        String accessToken  = jwtUtil.generateAccessToken(userId, role);
        String refreshToken = jwtUtil.generateRefreshToken(userId);

        // Access Token 쿠키 생성 (도메인: winnerteam.store / Secure / HttpOnly / SameSite=None)
        ResponseCookie access = ResponseCookie.from("ACCESS_TOKEN", accessToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofHours(1)).build();

        // Refresh Token 쿠키 생성
        ResponseCookie refresh = ResponseCookie.from("REFRESH_TOKEN", refreshToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofDays(14)).build();

        // 쿠키를 응답 헤더에 추가
        res.addHeader("Set-Cookie", access.toString());
        res.addHeader("Set-Cookie", refresh.toString());

        // JSON 바디로도 토큰 반환 (Postman 테스트용)
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write("""
        {
          "success": true,
          "message": "OAUTH_LOGIN_OK",
          "data": {
            "accessToken": "%s",
            "refreshToken": "%s"
          }
        }
        """.formatted(accessToken, refreshToken));
    }

    // OAuth 제공자별로 providerId 추출
    // google: sub, kakao: id, naver: id (response.id)
    private String extractProviderId(String provider, Map<String, Object> attrs) {
        Object id;
        switch (provider) {
            case "google":
                id = attrs.get("sub");
                break;
            case "kakao":
                id = attrs.get("id");
                break;
            case "naver":
                id = attrs.get("id");
                if (id == null && attrs.get("response") instanceof Map<?,?> resp) {
                    id = ((Map<?,?>) resp).get("id");
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
        if (id == null) throw new IllegalStateException("No providerId in attributes for " + provider);
        return String.valueOf(id);
    }
}
