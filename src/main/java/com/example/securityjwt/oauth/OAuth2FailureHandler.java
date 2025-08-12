package com.example.securityjwt.oauth;

import com.example.securityjwt.common.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

// OAuth2 로그인 실패 시 리다이렉트 없이 JSON 에러 바디로 응답
@Component
public class OAuth2FailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        String msg = (exception != null && exception.getMessage() != null)
                ? exception.getMessage()
                : "OAuth2 authentication failed";

        String body = toJson(ApiResponse.failure("소셜 로그인 실패: " + msg));
        response.getWriter().write(body);
    }

    private String toJson(Object o) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(o);
        } catch (Exception e) {
            return "{\"success\":false,\"message\":\"OAuth2 authentication failed\",\"data\":null}";
        }
    }
}
