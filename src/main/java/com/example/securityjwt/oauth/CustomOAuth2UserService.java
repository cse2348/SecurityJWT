package com.example.securityjwt.oauth;

import com.example.securityjwt.entity.User;
import com.example.securityjwt.oauth.userinfo.GoogleUserInfo;
import com.example.securityjwt.oauth.userinfo.KakaoUserInfo;
import com.example.securityjwt.oauth.userinfo.NaverUserInfo;
import com.example.securityjwt.oauth.userinfo.OAuth2UserInfo;
import com.example.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

// 소셜 사용자 정보를 표준화하고, 최초 로그인 시 자동 회원가입 처리
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
        OAuth2User raw = super.loadUser(req);
        Map<String, Object> rawAttributes = safeMap(raw.getAttributes(), "root");

        String registrationId = req.getClientRegistration().getRegistrationId();
        String provider = (registrationId == null ? "" : registrationId.toLowerCase(Locale.ROOT));

        OAuth2UserInfo info = switch (provider) {
            case "google" -> new GoogleUserInfo(rawAttributes);
            case "kakao"  -> new KakaoUserInfo(rawAttributes);
            case "naver"  -> new NaverUserInfo(rawAttributes);
            default -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider"),
                    "Unsupported provider: " + registrationId);
        };

        String providerId = String.valueOf(info.getProviderId()); // Long/Integer 대비
        String email = info.getEmail(); // 카카오는 null 가능
        String name  = info.getName();

        // 계정 식별은 provider + providerId (email 미동의 케이스 대응)
        User user = userRepository.findByProviderAndProviderId(info.getProvider(), providerId)
                .orElseGet(() -> {
                    User u = new User();
                    u.setProvider(info.getProvider());
                    u.setProviderId(providerId);
                    u.setEmail(email);
                    u.setName(name);
                    u.setRole("ROLE_USER");
                    return userRepository.save(u);
                });

        // 프로필 변경 동기화
        boolean updated = false;
        if (email != null && !email.equals(user.getEmail())) { user.setEmail(email); updated = true; }
        if (name  != null && !name.equals(user.getName()))  { user.setName(name);  updated = true; }
        if (updated) userRepository.save(user);

        String role = (user.getRole() != null && user.getRole().startsWith("ROLE_"))
                ? user.getRole() : "ROLE_USER";
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        // DefaultOAuth2User의 nameAttributeKey/attributes 설정
        String nameAttributeKey;
        Map<String, Object> attributesForPrincipal;

        switch (provider) {
            case "google" -> {
                nameAttributeKey = "sub";
                attributesForPrincipal = rawAttributes; // root에 sub/email/name 등
                requireKey(attributesForPrincipal, nameAttributeKey, "Google userinfo");
            }
            case "kakao" -> {
                nameAttributeKey = "id";
                attributesForPrincipal = rawAttributes; // root에 id, kakao_account, profile 등
                requireKey(attributesForPrincipal, nameAttributeKey, "Kakao userinfo");
            }
            case "naver" -> {
                nameAttributeKey = "id";
                Object responseObj = rawAttributes.get("response");
                if (!(responseObj instanceof Map<?, ?> response)) {
                    throw new OAuth2AuthenticationException(
                            new OAuth2Error("invalid_userinfo"),
                            "Naver userinfo does not contain 'response' object");
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> responseMap = new LinkedHashMap<>((Map<String, Object>) response);
                requireKey(responseMap, nameAttributeKey, "Naver userinfo.response");
                attributesForPrincipal = responseMap; // attributes로 'response' 맵 사용
            }
            default -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider"),
                    "Unsupported provider: " + registrationId);
        }

        return new DefaultOAuth2User(authorities, attributesForPrincipal, nameAttributeKey);
    }

    // ===== 유틸 =====
    private Map<String, Object> safeMap(Map<String, Object> src, String where) {
        if (src == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_userinfo"),
                    "Null attributes at: " + where);
        }
        return src;
    }

    private void requireKey(Map<String, Object> map, String key, String where) {
        if (!map.containsKey(key)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_userinfo"),
                    where + " missing key: " + key);
        }
    }
}
