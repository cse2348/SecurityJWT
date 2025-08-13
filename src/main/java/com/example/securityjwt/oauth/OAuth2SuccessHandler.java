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
        // provider 구하기 (google/kakao/naver)
        OAuth2AuthenticationToken oauth = (OAuth2AuthenticationToken) auth;
        String provider = oauth.getAuthorizedClientRegistrationId().toLowerCase(Locale.ROOT);

        // providerId 추출 (CustomOAuth2UserService에서 naver는 attributes를 response 맵으로 바꿔둠)
        OAuth2User principal = (OAuth2User) oauth.getPrincipal();
        Map<String, Object> attrs = principal.getAttributes();
        String providerId = extractProviderId(provider, attrs); // "sub"/"id" 등

        // DB 사용자 조회 (최초 로그인은 CustomOAuth2UserService에서 이미 가입 처리)
        User user = userRepository.findByProviderAndProviderId(provider, providerId)
                .orElseThrow(() -> new IllegalStateException("OAuth user not found after signup"));

        Long userId = user.getId();
        String role  = (user.getRole() != null && !user.getRole().isBlank()) ? user.getRole() : "ROLE_USER";

        // JWT 생성 —  userId 기반!
        String accessToken  = jwtUtil.generateAccessToken(userId, role);
        String refreshToken = jwtUtil.generateRefreshToken(userId);

        // 쿠키 심기 (SameSite=None; Secure; HttpOnly)
        ResponseCookie access = ResponseCookie.from("ACCESS_TOKEN", accessToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofDays(7)).build();

        ResponseCookie refresh = ResponseCookie.from("REFRESH_TOKEN", refreshToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofDays(30)).build();

        res.addHeader("Set-Cookie", access.toString());
        res.addHeader("Set-Cookie", refresh.toString());

        // 6) 응답
        res.setStatus(200);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write("{\"success\":true,\"message\":\"LOGIN_OK\"}");
    }

    private String extractProviderId(String provider, Map<String, Object> attrs) {
        Object id;
        switch (provider) {
            case "google":
                id = attrs.get("sub");               // 구글: sub
                break;
            case "kakao":
                id = attrs.get("id");                // 카카오: id (Long일 수 있음)
                break;
            case "naver":
                id = attrs.get("id");                // 네이버: response.id
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
