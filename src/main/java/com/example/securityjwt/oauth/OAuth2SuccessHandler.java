package com.example.securityjwt.oauth;

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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * OAuth2 로그인 성공 시
 * - 우리 서버가 Access/Refresh JWT 발급
 * - HttpOnly 쿠키로 내려주고
 * - 프론트 성공 URL로 리다이렉트
 */
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Value("${app.oauth.success-url:http://localhost:3000/login/success}")
    private String successUrl;

    // 쿠키 만료(초)
    @Value("${jwt.access-token-validity-sec:900}")
    private int accessMaxAge;
    @Value("${jwt.refresh-token-validity-sec:604800}")
    private int refreshMaxAge;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req,
                                        HttpServletResponse res,
                                        Authentication authentication) throws IOException {

        // 1) 소셜 사용자 속성 + provider 추출
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId = "unknown";
        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId(); // google/kakao/naver
        }

        // 2) provider별 파싱 → providerId 로 사용자 식별
        OAuth2UserInfo info = switch (registrationId.toLowerCase()) {
            case "google" -> new GoogleUserInfo(attributes);
            case "kakao"  -> new KakaoUserInfo(attributes);
            case "naver"  -> new NaverUserInfo(attributes);
            default -> throw new IllegalStateException("Unsupported provider: " + registrationId);
        };

        // 3) DB 사용자 조회 (CustomOAuth2UserService에서 이미 저장되어 있어야 함)
        Optional<User> opt = userRepository.findByProviderAndProviderId(info.getProvider(), info.getProviderId());
        if (opt.isEmpty()) {
            // 방어적 처리: 이 경우는 거의 없지만, 없으면 자동 생성
            User u = new User();
            u.setProvider(info.getProvider());
            u.setProviderId(info.getProviderId());
            u.setEmail(info.getEmail());
            u.setName(info.getName());
            u.setRole("ROLE_USER");
            userRepository.save(u);
            opt = Optional.of(u);
        }
        User user = opt.get();

        // 4) JWT 발급
        String accessToken  = jwtUtil.generateAccessToken(user.getId(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        // (선택) 사용자 엔티티에 최신 refreshToken 저장(재발급/로그아웃 시 검증용)
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        // 5) HttpOnly 쿠키로 내려주기
        addHttpOnlyCookie(res, "ACCESS_TOKEN", accessToken, accessMaxAge);
        addHttpOnlyCookie(res, "REFRESH_TOKEN", refreshToken, refreshMaxAge);

        // SameSite=None 설정(서블릿 기본 Cookie에는 없어서 헤더로 한 번 더 지정)
        addSameSiteNone(res, "ACCESS_TOKEN", accessToken, accessMaxAge);
        addSameSiteNone(res, "REFRESH_TOKEN", refreshToken, refreshMaxAge);

        // 6) 프론트 성공 URL로 리다이렉트
        res.sendRedirect(successUrl);
    }

    /**
     * 기본 HttpOnly/Secure 쿠키 추가
     */
    private void addHttpOnlyCookie(HttpServletResponse res, String name, String value, int maxAgeSec) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);  // JS 접근 불가 → XSS 완화
        cookie.setSecure(true);    // HTTPS에서만 전송
        cookie.setPath("/");       // 전체 경로
        cookie.setMaxAge(maxAgeSec);
        res.addCookie(cookie);
    }

    /**
     * SameSite=None 설정을 위해 Set-Cookie 헤더를 직접 추가
     * - 일부 서블릿/컨테이너 버전에서 Cookie API에 SameSite 속성이 없어 수동 추가가 필요
     */
    private void addSameSiteNone(HttpServletResponse res, String name, String value, int maxAgeSec) {
        String header = String.format(
                "%s=%s; Max-Age=%d; Path=/; Secure; HttpOnly; SameSite=None",
                name, value, maxAgeSec
        );
        res.addHeader("Set-Cookie", header);
    }
}
