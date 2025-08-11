package com.example.securityjwt.oauth.userinfo;

import java.util.Map;

// Kakao 사용자 정보 파서 -> 대표 키: id, kakao_account.email, kakao_account.profile.nickname (이메일은 동의 항목에 따라 없을 수 있음)
@SuppressWarnings("unchecked")
public class KakaoUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attr;

    public KakaoUserInfo(Map<String, Object> attr) {
        this.attr = attr;
    }

    @Override
    public String getProvider() {
        return "KAKAO";
    }

    @Override
    public String getProviderId() {
        Object id = attr.get("id");
        return id == null ? null : id.toString();
    }

    @Override
    public String getEmail() {
        Map<String, Object> account = (Map<String, Object>) attr.get("kakao_account");
        if (account == null) return null;
        Object email = account.get("email");
        return email == null ? null : email.toString();
    }

    @Override
    public String getName() {
        Map<String, Object> account = (Map<String, Object>) attr.get("kakao_account");
        if (account == null) return null;
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");
        if (profile == null) return null;
        Object nick = profile.get("nickname");
        return nick == null ? null : nick.toString();
    }
}
