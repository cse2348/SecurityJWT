package com.example.securityjwt.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.SerializationUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

// OAuth2 인증 요청을 쿠키에 저장하고 불러오는 Repository 구현체
public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    // 쿠키 이름
    public static final String OAUTH2_AUTH_REQUEST_COOKIE_NAME = "OAUTH2_AUTH_REQ";
    // 쿠키 만료 시간 (초)
    public static final int COOKIE_EXPIRE_SECONDS = 180;

    // 요청에서 쿠키를 읽어 OAuth2AuthorizationRequest 객체로 변환
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return CookieUtils.getCookie(request, OAUTH2_AUTH_REQUEST_COOKIE_NAME)
                .map(c -> deserialize(c.getValue()))
                .orElse(null);
    }

    // OAuth2AuthorizationRequest 객체를 쿠키에 저장
    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authReq,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authReq == null) {
            // null이면 기존 쿠키 삭제
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTH_REQUEST_COOKIE_NAME);
            return;
        }
        // 직렬화 후 Base64 인코딩하여 쿠키에 저장
        CookieUtils.addCookie(response, OAUTH2_AUTH_REQUEST_COOKIE_NAME,
                serialize(authReq), COOKIE_EXPIRE_SECONDS);
    }

    // 쿠키에서 OAuth2AuthorizationRequest 객체를 제거 후 반환
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest req = loadAuthorizationRequest(request);
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTH_REQUEST_COOKIE_NAME);
        return req;
    }

    // 객체 직렬화 후 Base64 문자열로 변환
    private String serialize(OAuth2AuthorizationRequest obj) {
        byte[] bytes = SerializationUtils.serialize(obj);
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

    // Base64 문자열을 디코딩 후 객체로 역직렬화
    private OAuth2AuthorizationRequest deserialize(String val) {
        byte[] bytes = Base64.getUrlDecoder().decode(val.getBytes(StandardCharsets.UTF_8));
        return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(bytes);
    }
}
