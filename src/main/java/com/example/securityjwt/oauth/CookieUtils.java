package com.example.securityjwt.oauth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;
import java.util.Optional;

//  쿠키 관련 유틸 클래스 -> 쿠키 조회, 생성, 삭제 기능 제공
public class CookieUtils {

    // 요청에서 특정 이름의 쿠키를 Optional로 반환
    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            return Arrays.stream(cookies)
                    .filter(c -> c.getName().equals(name))
                    .findFirst();
        }
        return Optional.empty();
    }

    // 새로운 쿠키를 생성하여 응답에 추가
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");           // 모든 경로에서 쿠키 전송
        cookie.setHttpOnly(true);      // JavaScript에서 접근 불가
        cookie.setMaxAge(maxAge);      // 유효기간 설정
        response.addCookie(cookie);
    }

    // 요청에서 특정 쿠키를 찾아 삭제 -> 삭제는 값 비우기 + 유효기간 0초로 설정하여 만료 처리
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (c.getName().equals(name)) {
                    c.setValue("");
                    c.setPath("/");
                    c.setMaxAge(0); // 즉시 만료
                    response.addCookie(c);
                }
            }
        }
    }
}
