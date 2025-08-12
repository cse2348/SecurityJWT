package com.example.securityjwt.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class OAuth2FailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.AuthenticationException exception) {
        try { // 실패 응답 형식 통일을 위해 401로 설정
            // 예외 메시지에 따라 다른 응답을 내려도 됨
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/json");
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "status", "fail",
                    "error", exception.getClass().getSimpleName(),
                    "message", exception.getMessage()
            ));
        } catch (Exception ignored) {}
    }
}
