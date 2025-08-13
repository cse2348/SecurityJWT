package com.example.securityjwt.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Component;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class OAuth2FailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) {
        // 요청 단위 추적을 위한 traceId 생성
        String traceId = UUID.randomUUID().toString();
        try {
            // 실패 로그 출력
            log.warn("[OAuth2][FAIL][{}] type={} msg={}", traceId, exception.getClass().getSimpleName(), exception.getMessage());

            // 기존 세션 무효화
            if (request.getSession(false) != null) {
                request.getSession(false).invalidate();
            }
            // 기존 토큰 쿠키 삭제
            clearCookie(response, "ACCESS_TOKEN", "winnerteam.store");
            clearCookie(response, "REFRESH_TOKEN", "winnerteam.store");

            // 기본 에러 코드와 메시지
            String errorCode = "auth_failure";
            String message = exception.getMessage();
            String provider = guessProviderFromRequest(request);

            // OAuth2AuthenticationException인 경우 세부 에러 코드 설정
            if (exception instanceof OAuth2AuthenticationException oae) {
                OAuth2Error err = oae.getError();
                if (err != null && err.getErrorCode() != null) {
                    errorCode = err.getErrorCode();
                }
            }

            // 응답 바디 구성
            Map<String, Object> body = new HashMap<>();
            body.put("status", "fail");
            body.put("error", errorCode);
            body.put("message", safeMessage(message));
            body.put("provider", provider);
            body.put("traceId", traceId);

            // CORS 및 응답 헤더 설정
            response.setHeader("Access-Control-Allow-Origin", "https://winnerteam.store");
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // JSON 응답 전송
            objectMapper.writeValue(response.getWriter(), body);
            response.getWriter().flush();

        } catch (Exception e) {
            // 실패 처리 중 예외 발생 시 기본 에러 응답 전송
            log.error("[OAuth2][FAIL][{}] failureHandler error: {}", traceId, e.toString());
            try {
                response.resetBuffer();
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.setContentType("application/json;charset=UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                objectMapper.writeValue(response.getWriter(), Map.of(
                        "status", "fail",
                        "error", "auth_failure",
                        "message", "OAuth2 authentication failed",
                        "traceId", traceId
                ));
            } catch (Exception ignored) {}
        }
    }

    // 쿠키 삭제 유틸
    private void clearCookie(HttpServletResponse res, String name, String domain) {
        Cookie cookie = new Cookie(name, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setDomain(domain);
        res.addCookie(cookie);
    }

    // 요청 URI 또는 Referer로부터 OAuth2 제공자 추측
    private String guessProviderFromRequest(HttpServletRequest req) {
        String uri = req.getRequestURI();
        if (uri != null) {
            if (uri.contains("/oauth2/authorize/google") || uri.contains("/oauth2/callback/google")) return "google";
            if (uri.contains("/oauth2/authorize/kakao")  || uri.contains("/oauth2/callback/kakao"))  return "kakao";
            if (uri.contains("/oauth2/authorize/naver")  || uri.contains("/oauth2/callback/naver"))  return "naver";
        }
        String ref = req.getHeader("Referer");
        if (ref != null) {
            if (ref.contains("/oauth2/authorize/google")) return "google";
            if (ref.contains("/oauth2/authorize/kakao"))  return "kakao";
            if (ref.contains("/oauth2/authorize/naver"))  return "naver";
        }
        return "unknown";
    }

    // 메시지 길이 제한 및 기본 메시지 처리
    private String safeMessage(String msg) {
        if (msg == null || msg.isBlank()) return "Authentication failed";
        return msg.length() > 500 ? msg.substring(0, 500) + "..." : msg;
    }
}
