package com.example.securityjwt.oauth;

import com.example.securityjwt.common.ApiResponse;
import com.example.securityjwt.dto.TokenResponse;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.jwt.JwtUtil;
import com.example.securityjwt.oauth.userinfo.GoogleUserInfo;
import com.example.securityjwt.oauth.userinfo.KakaoUserInfo;
import com.example.securityjwt.oauth.userinfo.NaverUserInfo;
import com.example.securityjwt.oauth.userinfo.OAuth2UserInfo;
import com.example.securityjwt.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

// OAuth2 로그인 성공 시 서버가 Access/Refresh JWT 발급 -> HttpOnly 쿠키로 내려주고 JSON 바디(TokenResponse)를 바로 반환 (리다이렉트 없음)
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    // 쿠키 만료(초) — JwtUtil의 만료와 굳이 동일할 필요는 없지만 맞춰두면 편함
    private final int accessMaxAge  = 60 * 60;          // 1h
    private final int refreshMaxAge = 14 * 24 * 60 * 60; // 14d

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req,
                                        HttpServletResponse res,
                                        Authentication authentication) throws IOException {

        // 1) 사용자 속성 + provider 추출
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId = (authentication instanceof OAuth2AuthenticationToken t)
                ? t.getAuthorizedClientRegistrationId()
                : "unknown";

        // 2) provider별 파싱
        OAuth2UserInfo info = switch (registrationId.toLowerCase()) {
            case "google" -> new GoogleUserInfo(attributes);
            case "kakao"  -> new KakaoUserInfo(attributes);
            case "naver"  -> new NaverUserInfo(attributes);
            default -> throw new IllegalStateException("Unsupported provider: " + registrationId);
        };

        // 3) 사용자 조회(없으면 생성) — 보통 CustomOAuth2UserService에서 이미 생성됨
        User user = userRepository.findByProviderAndProviderId(info.getProvider(), info.getProviderId())
                .orElseGet(() -> {
                    User u = new User();
                    u.setProvider(info.getProvider());
                    u.setProviderId(info.getProviderId());
                    u.setEmail(info.getEmail());
                    u.setName(info.getName());
                    u.setRole("ROLE_USER");
                    return userRepository.save(u);
                });

        // 4) JWT 발급 (subject=userId, access에 role)
        String accessToken  = jwtUtil.generateAccessToken(user.getId(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        // DB에 refresh 저장(재발급 검증용)
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        // 5) HttpOnly 쿠키 세팅
        addHttpOnlyCookie(res, "ACCESS_TOKEN", accessToken, accessMaxAge);
        addHttpOnlyCookie(res, "REFRESH_TOKEN", refreshToken, refreshMaxAge);
        // SameSite=None 대응(서블릿 Cookie API 한계)
        addSameSiteNoneHeader(res, "ACCESS_TOKEN", accessToken, accessMaxAge);
        addSameSiteNoneHeader(res, "REFRESH_TOKEN", refreshToken, refreshMaxAge);

        // 6) JSON 바디로 토큰도 함께 내려줌 (Postman 확인 용이)
        TokenResponse body = TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write(Jsons.toJson(ApiResponse.success("소셜 로그인 성공", body)));
    }

    private void addHttpOnlyCookie(HttpServletResponse res, String name, String value, int maxAgeSec) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSec);
        res.addCookie(cookie);
    }

    private void addSameSiteNoneHeader(HttpServletResponse res, String name, String value, int maxAgeSec) {
        String header = String.format(
                "%s=%s; Max-Age=%d; Path=/; Secure; HttpOnly; SameSite=None",
                name, value, maxAgeSec
        );
        res.addHeader("Set-Cookie", header);
    }

    //  JSON 헬퍼 (Object → JSON 문자열) ; Jackson을 이미 의존성에 두고 있으므로 사용
    static class Jsons {
        static String toJson(Object o) {
            try {
                return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(o);
            } catch (Exception e) {
                return "{\"success\":true,\"message\":\"ok\",\"data\":null}";
            }
        }
    }
}
