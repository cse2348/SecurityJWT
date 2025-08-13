package com.example.securityjwt.oauth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;
import java.util.Optional;

public class CookieUtils {
    public static Optional<Cookie> getCookie(HttpServletRequest req, String name) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return Optional.empty();
        return Arrays.stream(cookies).filter(c -> c.getName().equals(name)).findFirst();
    }

    public static void addCookie(HttpServletResponse res, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "None");
        res.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest req, HttpServletResponse res, String name) {
        getCookie(req, name).ifPresent(c -> {
            Cookie cookie = new Cookie(name, null);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setAttribute("SameSite", "None");
            res.addCookie(cookie);
        });
    }
}
