package com.example.securityjwt.oauth.userinfo;

// 소셜 제공자별 사용자 정보 응답을 서비스에서 공통으로 쓰기 위한 인터페이스
public interface OAuth2UserInfo {
    String getProvider();    // GOOGLE / KAKAO / NAVER
    String getProviderId();  // 소셜 고유 사용자 ID
    String getEmail();       // 카카오/네이버는 null일 수 있음
    String getName();
}
