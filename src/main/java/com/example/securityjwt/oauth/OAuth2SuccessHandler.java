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
        OAuth2AuthenticationToken oauth = (OAuth2AuthenticationToken) auth;
        String provider = oauth.getAuthorizedClientRegistrationId().toLowerCase(Locale.ROOT);

        OAuth2User principal = (OAuth2User) oauth.getPrincipal();
        Map<String, Object> attrs = principal.getAttributes();
        String providerId = extractProviderId(provider, attrs); // google: sub / kakao: id / naver: response.id

        // 최초 로그인은 CustomOAuth2UserService에서 가입 처리됨
        User user = userRepository.findByProviderAndProviderId(provider, providerId)
                .orElseThrow(() -> new IllegalStateException("OAuth user not found after signup"));

        Long userId = user.getId();
        String role = (user.getRole() != null && !user.getRole().isBlank()) ? user.getRole() : "ROLE_USER";

        // JWT 생성 (userId 기반)
        String accessToken  = jwtUtil.generateAccessToken(userId, role);
        String refreshToken = jwtUtil.generateRefreshToken(userId);

        // 쿠키(도메인: winnerteam.store / SameSite=None / Secure / HttpOnly)
        ResponseCookie access = ResponseCookie.from("ACCESS_TOKEN", accessToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofHours(1)).build();

        ResponseCookie refresh = ResponseCookie.from("REFRESH_TOKEN", refreshToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofDays(14)).build();

        res.addHeader("Set-Cookie", access.toString());
        res.addHeader("Set-Cookie", refresh.toString());

        // JSON 바디로도 동시 반환 → Postman 테스트 편의성
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
