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

// OAuth2 로그인 시 소셜 프로바이더에서 받은 사용자 정보를 서비스의 User 모델로 정규화하고 최초 로그인 시 자동 회원가입 처리
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
        // 소셜에서 사용자 속성(raw attributes) 조회
        OAuth2User raw = super.loadUser(req);
        Map<String, Object> rawAttributes = safeMap(raw.getAttributes(), "root");

        // provider 식별자: google / kakao / naver
        String registrationId = req.getClientRegistration().getRegistrationId();
        String provider = (registrationId == null ? "" : registrationId.toLowerCase(Locale.ROOT));

        // 제공자별 응답 형태를 공통 인터페이스로 매핑 (자동 회원가입용)
        OAuth2UserInfo info = switch (provider) {
            case "google" -> new GoogleUserInfo(rawAttributes);
            case "kakao"  -> new KakaoUserInfo(rawAttributes);
            case "naver"  -> new NaverUserInfo(rawAttributes);
            default -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider"), "Unsupported provider: " + registrationId);
        };

        // providerId는 Long/Integer일 수도 있으므로 문자열로 통일
        String providerId = String.valueOf(info.getProviderId());
        String email      = info.getEmail(); // 카카오는 동의 안 하면 null일 수 있음
        String name       = info.getName();

        // 이메일이 없더라도 계정 식별은 provider + providerId로 한다.
        //   (email을 unique로 쓰면 카카오에서 최초 로그인 시 실패 가능)
        User user = userRepository.findByProviderAndProviderId(info.getProvider(), providerId)
                .orElseGet(() -> {
                    User u = new User();
                    u.setProvider(info.getProvider());
                    u.setProviderId(providerId);
                    u.setEmail(email);          // null 가능
                    u.setName(name);
                    u.setRole("ROLE_USER");
                    return userRepository.save(u);
                });

        // 재로그인 시 프로필/이메일 변경 동기화(있으면 업데이트)
        boolean updated = false;
        if (email != null && !email.equals(user.getEmail())) {
            user.setEmail(email); updated = true;
        }
        if (name != null && !name.equals(user.getName())) {
            user.setName(name); updated = true;
        }
        if (updated) userRepository.save(user);

        // 권한 준비 (ROLE_ prefix 강제)
        String role = (user.getRole() != null && user.getRole().startsWith("ROLE_"))
                ? user.getRole() : "ROLE_USER";
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        // DefaultOAuth2User에 넘길 attributes & nameAttributeKey 정리
        //    - google: attributes=raw,  key="sub"
        //    - kakao : attributes=raw,  key="id"
        //    - naver : attributes=responseMap, key="id"
        String nameAttributeKey;
        Map<String, Object> attributesForPrincipal;

        switch (provider) {
            case "google" -> {
                nameAttributeKey = "sub";
                attributesForPrincipal = rawAttributes; // 구글은 root에 sub/email/name 등이 존재
                requireKey(attributesForPrincipal, nameAttributeKey, "Google userinfo");
            }
            case "kakao" -> {
                nameAttributeKey = "id";
                attributesForPrincipal = rawAttributes; // 카카오는 root에 id, kakao_account, profile 등이 존재
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
                attributesForPrincipal = responseMap; // DefaultOAuth2User의 attributes로 'response' 맵을 사용
            }
            default -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider"), "Unsupported provider: " + registrationId);
        }

        // DefaultOAuth2User 생성 후 반환
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
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_userinfo"),
                    where + " missing key: " + key);
        }
    }
}
