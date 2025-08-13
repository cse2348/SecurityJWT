package com.example.securityjwt.oauth.userinfo;

import java.util.Map;

// Kakao 사용자 정보 파서 -> 대표 키: id, kakao_account.email, kakao_account.profile.nickname (이메일은 동의 항목에 따라 없을 수 있음)
@SuppressWarnings("unchecked")
public class KakaoUserInfo implements OAuth2UserInfo {

    // Kakao가 반환한 사용자 정보(JSON)를 key-value 형태로 저장
    private final Map<String, Object> attr;

    // 생성자 - Kakao OAuth2 응답 데이터를 주입 -> @param attr Kakao OAuth2 user info JSON -> Map 변환 값
    public KakaoUserInfo(Map<String, Object> attr) {
        this.attr = attr;
    }

    // 제공자 이름 반환
    @Override
    public String getProvider() {
        return "KAKAO";
    }

    // Kakao 계정의 고유 ID(id) 반환
    @Override
    public String getProviderId() {
        Object id = attr.get("id");
        return id == null ? null : id.toString();
    }

    // 사용자 이메일(email) 반환
    @Override
    public String getEmail() {
        Map<String, Object> account = (Map<String, Object>) attr.get("kakao_account");
        if (account == null) return null;
        Object email = account.get("email");
        return email == null ? null : email.toString();
    }

    // 사용자 닉네임(profile.nickname) 반환
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
