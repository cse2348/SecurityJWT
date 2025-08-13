package com.example.securityjwt.oauth;

import com.example.securityjwt.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws IOException {
        String username = auth.getName();
        String roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String accessToken  = jwtUtil.createAccessToken(username, roles);
        String refreshToken = jwtUtil.createRefreshToken(username);

        // ACCESS_TOKEN 쿠키
        ResponseCookie access = ResponseCookie.from("ACCESS_TOKEN", accessToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofDays(7)).build();
        // REFRESH_TOKEN 쿠키 (원하면 HttpOnly+Longer)
        ResponseCookie refresh = ResponseCookie.from("REFRESH_TOKEN", refreshToken)
                .httpOnly(true).secure(true).sameSite("None")
                .domain("winnerteam.store").path("/").maxAge(Duration.ofDays(30)).build();

        res.addHeader("Set-Cookie", access.toString());
        res.addHeader("Set-Cookie", refresh.toString());

        res.setStatus(200);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write("{\"success\":true,\"message\":\"LOGIN_OK\"}");
    }
}
