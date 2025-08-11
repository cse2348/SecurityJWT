package com.example.securityjwt.oauth.userinfo;

import java.util.Map;

// Naver 사용자 정보 파서 -> 응답 구조: { response: { id, email, name, ... } }  (이메일은 동의 항목에 따라 없을 수 있음)
@SuppressWarnings("unchecked")
public class NaverUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attr;

    public NaverUserInfo(Map<String, Object> attr) {
        this.attr = attr;
    }

    private Map<String, Object> response() {
        Object res = attr.get("response");
        return (Map<String, Object>) res;
    }

    @Override
    public String getProvider() {
        return "NAVER";
    }

    @Override
    public String getProviderId() {
        Map<String, Object> r = response();
        if (r == null) return null;
        Object id = r.get("id");
        return id == null ? null : id.toString();
    }

    @Override
    public String getEmail() {
        Map<String, Object> r = response();
        if (r == null) return null;
        Object email = r.get("email");
        return email == null ? null : email.toString();
    }

    @Override
    public String getName() {
        Map<String, Object> r = response();
        if (r == null) return null;
        Object name = r.get("name");
        return name == null ? null : name.toString();
    }
}
