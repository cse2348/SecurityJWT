package com.example.securityjwt.oauth.userinfo;

import java.util.Map;

//  Google OAuth2 로그인 사용자 정보 파서 -> Google의 사용자 정보 응답(JSON)을 Map 형태로 받아 필요한 필드 추출
public class GoogleUserInfo implements OAuth2UserInfo {

    // Google이 반환한 사용자 정보(JSON)를 key-value 형태로 저장
    private final Map<String, Object> attr;

    // 생성자 - Google OAuth2 응답 데이터를 주입 -> @param attr Google OAuth2 user info JSON -> Map 변환 값
    public GoogleUserInfo(Map<String, Object> attr) {
        this.attr = attr;
    }

    //  제공자 이름 반환
    @Override
    public String getProvider() {
        return "GOOGLE";
    }

    // Google 계정의 고유 ID 반환
    @Override
    public String getProviderId() {
        Object sub = attr.get("sub");
        return sub == null ? null : sub.toString();
    }

    // 사용자 이메일(email) 반환
    @Override
    public String getEmail() {
        Object email = attr.get("email");
        return email == null ? null : email.toString();
    }

    // 사용자 이름(name) 반환
    @Override
    public String getName() {
        Object name = attr.get("name");
        return name == null ? null : name.toString();
    }
}
