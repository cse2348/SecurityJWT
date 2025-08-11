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

import java.util.*;

/**
 * OAuth2 로그인 시 소셜 프로바이더에서 받은 사용자 정보를
 * - 우리 서비스의 User 모델로 정규화하고
 * - 최초 로그인 시 자동 회원가입 처리
 *
 * ⚠️ DefaultOAuth2User 생성 시 nameAttributeKey가 attributes에 실제로 존재해야 함
 *   - google: root에 "sub" 존재 → 그대로 사용
 *   - kakao : root에 "id"   존재 → 그대로 사용
 *   - naver : root가 "response" 맵 → "response" 맵을 attributes로 교체하고 nameAttributeKey="id"
 */
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
        // 1) 소셜에서 사용자 속성(raw attributes) 조회
        OAuth2User raw = super.loadUser(req);
        Map<String, Object> rawAttributes = raw.getAttributes();

        // 2) provider 식별자: google / kakao / naver
        String registrationId = req.getClientRegistration().getRegistrationId();
        String provider = registrationId == null ? "" : registrationId.toLowerCase(Locale.ROOT);

        // 3) 제공자별 응답 형태를 공통 인터페이스로 매핑 (자동 회원가입용)
        OAuth2UserInfo info = switch (provider) {
            case "google" -> new GoogleUserInfo(rawAttributes);
            case "kakao"  -> new KakaoUserInfo(rawAttributes);
            case "naver"  -> new NaverUserInfo(rawAttributes);
            default -> throw new OAuth2AuthenticationException(
                    new OAuth2Error("unsupported_provider"), "Unsupported provider: " + registrationId);
        };

        // 4) 자동 회원가입 또는 기존 사용자 조회
        User user = userRepository.findByProviderAndProviderId(info.getProvider(), info.getProviderId())
                .orElseGet(() -> {
                    User u = new User();
                    u.setProvider(info.getProvider());
                    u.setProviderId(info.getProviderId());
                    u.setEmail(info.getEmail());  // 카카오/네이버는 null일 수 있음
                    u.setName(info.getName());
                    u.setRole("ROLE_USER");
                    return userRepository.save(u);
                });

        // 5) 권한 준비
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(user.getRole()));

        // 6) DefaultOAuth2User에 넘길 attributes & nameAttributeKey 정리
        //    - google: attributes=raw,  key="sub"
        //    - kakao : attributes=raw,  key="id"
        //    - naver : attributes=responseMap, key="id"
        String nameAttributeKey;
        Map<String, Object> attributesForPrincipal;

        switch (provider) {
            case "google" -> {
                nameAttributeKey = "sub";
                attributesForPrincipal = rawAttributes; // 구글은 root에 sub/email/name 등이 존재
            }
            case "kakao" -> {
                nameAttributeKey = "id";
                attributesForPrincipal = rawAttributes; // 카카오는 root에 id, kakao_account, profile 등이 존재
            }
            case "naver" -> {
                nameAttributeKey = "id";
                Object responseObj = rawAttributes.get("response");
                if (!(responseObj instanceof Map<?, ?> response)) {
                    throw new OAuth2AuthenticationException(
                            new OAuth2Error("invalid_userinfo"),
                            "Naver userinfo does not contain 'response' object");
                }
                // 타입 안전하게 복사
                @SuppressWarnings("unchecked")
                Map<String, Object> responseMap = new LinkedHashMap<>((Map<String, Object>) response);
                attributesForPrincipal = responseMap; // DefaultOAuth2User의 attributes로 'response' 맵을 사용
            }
            default -> {
                // 이 케이스는 위 switch에서 예외 처리했지만, 컴파일러를 위해 한 번 더 방어
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("unsupported_provider"), "Unsupported provider: " + registrationId);
            }
        }

        // 7) DefaultOAuth2User 생성 후 반환
        return new DefaultOAuth2User(authorities, attributesForPrincipal, nameAttributeKey);
    }
}
