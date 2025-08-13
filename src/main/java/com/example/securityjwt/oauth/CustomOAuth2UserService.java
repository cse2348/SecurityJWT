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
            case "kakao" -> new KakaoUserInfo(rawAttributes);
            case "naver" -> new NaverUserInfo(rawAttributes);
            default -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider"),
                    "Unsupported provider: " + registrationId);
        };

        String providerId = String.valueOf(info.getProviderId());
        String email = info.getEmail();
        String name = info.getName();

        // provider와 providerId로 이미 가입된 사용자인지 확인
        Optional<User> userOptional = userRepository.findByProviderAndProviderId(info.getProvider(), providerId);
        User user;

        if (userOptional.isPresent()) {
            // 이미 해당 소셜 계정으로 가입된 경우 -> 기존 정보 업데이트 (이름, 이메일 등)
            user = userOptional.get();
            boolean updated = false;
            if (email != null && !email.equals(user.getEmail())) { user.setEmail(email); updated = true; }
            if (name != null && !name.equals(user.getName())) { user.setName(name); updated = true; }
            if (updated) {
                user = userRepository.save(user);
            }
        } else {
            // 해당 소셜 계정으로 가입된 적이 없는 경우 -> 이메일로 이미 가입된 사용자인지 확인
            Optional<User> userByEmailOptional = (email != null) ? userRepository.findByEmail(email) : Optional.empty();

            if (userByEmailOptional.isPresent()) {
                // 이메일이 이미 존재하면 -> 기존 계정에 소셜 정보 연동
                user = userByEmailOptional.get();
                user.setProvider(info.getProvider());
                user.setProviderId(providerId);
            } else {
                // 이메일도 존재하지 않으면 -> 신규 회원가입
                user = new User();
                user.setProvider(info.getProvider());
                user.setProviderId(providerId);
                user.setEmail(email);
                user.setName(name);
                user.setRole("ROLE_USER");
            }
            user = userRepository.save(user);
        }

        String role = (user.getRole() != null && user.getRole().startsWith("ROLE_"))
                ? user.getRole() : "ROLE_USER";
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        String nameAttributeKey;
        Map<String, Object> attributesForPrincipal;

        switch (provider) {
            case "google" -> {
                nameAttributeKey = "sub";
                attributesForPrincipal = rawAttributes;
                requireKey(attributesForPrincipal, nameAttributeKey, "Google userinfo");
            }
            case "kakao" -> {
                nameAttributeKey = "id";
                attributesForPrincipal = rawAttributes;
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
                attributesForPrincipal = responseMap;
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