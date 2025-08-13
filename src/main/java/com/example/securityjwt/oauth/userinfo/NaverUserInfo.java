package com.example.securityjwt.oauth.userinfo;

import java.util.Map;

// Naver 사용자 정보 파서 -> 응답 구조: { response: { id, email, name, ... } } (이메일은 동의 항목에 따라 없을 수 있음)
@SuppressWarnings("unchecked")
public class NaverUserInfo implements OAuth2UserInfo {

    // Naver가 반환한 사용자 정보(JSON)를 key-value 형태로 저장
    private final Map<String, Object> attr;

    // 생성자 - Naver OAuth2 응답 데이터를 주입 -> @param attr Naver OAuth2 user info JSON -> Map 변환 값
    public NaverUserInfo(Map<String, Object> attr) {
        this.attr = attr;
    }

    // 내부 response 맵 접근 헬퍼
    private Map<String, Object> response() {
        Object res = attr.get("response");
        return (Map<String, Object>) res;
    }

    // 제공자 이름 반환
    @Override
    public String getProvider() {
        return "NAVER";
    }

    // Naver 계정의 고유 ID(id) 반환
    @Override
    public String getProviderId() {
        Map<String, Object> r = response();
        if (r == null) return null;
        Object id = r.get("id");
        return id == null ? null : id.toString();
    }

    // 사용자 이메일(email) 반환
    @Override
    public String getEmail() {
        Map<String, Object> r = response();
        if (r == null) return null;
        Object email = r.get("email");
        return email == null ? null : email.toString();
    }

    // 사용자 이름(name) 반환
    @Override
    public String getName() {
        Map<String, Object> r = response();
        if (r == null) return null;
        Object name = r.get("name");
        return name == null ? null : name.toString();
    }
}
