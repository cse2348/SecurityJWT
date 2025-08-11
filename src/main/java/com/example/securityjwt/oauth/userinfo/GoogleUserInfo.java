package com.example.securityjwt.oauth.userinfo;

import java.util.Map;

// Google 사용자 정보 파서 -> 대표 키: sub(고유ID), email, name, picture등...
public class GoogleUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attr;

    public GoogleUserInfo(Map<String, Object> attr) {
        this.attr = attr;
    }

    @Override
    public String getProvider() {
        return "GOOGLE";
    }

    @Override
    public String getProviderId() {
        Object sub = attr.get("sub");
        return sub == null ? null : sub.toString();
    }

    @Override
    public String getEmail() {
        Object email = attr.get("email");
        return email == null ? null : email.toString();
    }

    @Override
    public String getName() {
        Object name = attr.get("name");
        return name == null ? null : name.toString();
    }
}
