package com.example.securityjwt.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
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
                                        org.springframework.security.core.AuthenticationException exception) {
        String traceId = UUID.randomUUID().toString();
        try {
            // ===== 1) 로그 =====
            log.warn("[OAuth2][FAIL][{}] type={} msg={}", traceId, exception.getClass().getSimpleName(), exception.getMessage());

            // ===== 2) 남아있을 수 있는 인가요청/세션/쿠키 정리 =====
            if (request.getSession(false) != null) {
                // 세션 기반 저장소(HttpSessionOAuth2AuthorizationRequestRepository) 사용 시
                request.getSession(false).invalidate();
            }
            // ACCESS/REFRESH 토큰 쿠키가 혹시 남아있다면 제거 (도메인/경로는 발급시와 동일)
            clearCookie(response, "ACCESS_TOKEN", "winnerteam.store");
            clearCookie(response, "REFRESH_TOKEN", "winnerteam.store");

            // ===== 3) 오류 코드/메시지 정규화 =====
            String errorCode = "auth_failure";
            String message = exception.getMessage();
            String provider = guessProviderFromRefererOrRequest(request);

            if (exception instanceof OAuth2AuthenticationException oauthEx) {
                OAuth2Error err = oauthEx.getError();
                if (err != null && err.getErrorCode() != null) {
                    errorCode = err.getErrorCode(); // e.g., invalid_request, access_denied
                }
            }

            // KOE(카카오) 코드 힌트 제공
            Map<String, String> hints = new HashMap<>();
            if (message != null) {
                if (message.contains("KOE205")) {
                    hints.put("hint", "카카오 Redirect URI 불일치(KOE205). 콘솔/서버의 콜백 URL이 한 글자라도 달라요.");
                } else if (message.contains("KOE006")) {
                    hints.put("hint", "카카오 등록되지 않은 Redirect URI(KOE006). 콘솔에 콜백을 추가해야 합니다.");
                } else if (message.contains("invalid_request")) {
                    hints.put("hint", "필수 파라미터 누락 또는 스코프/리다이렉트 URI 불일치 가능성이 있어요.");
                } else if (message.contains("authorization_request_not_found")) {
                    hints.put("hint", "인가요청 상태를 못 찾았습니다. 세션/저장소 설정 확인(IF_REQUIRED + HttpSession 저장소).");
                }
            }

            // ===== 4) CORS/컨텐츠타입/상태코드 =====
            // (백엔드 CORS 필터가 있지만 실패 핸들러에서 한 번 더 보강)
            response.setHeader("Access-Control-Allow-Origin", "https://winnerteam.store");
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401

            // ===== 5) 응답 페이로드 =====
            Map<String, Object> body = new HashMap<>();
            body.put("status", "fail");
            body.put("error", errorCode);
            body.put("message", safeMessage(message));
            body.put("provider", provider);
            body.put("traceId", traceId);
            body.putAll(hints);

            objectMapper.writeValue(response.getWriter(), body);
            response.getWriter().flush();

        } catch (Exception e) {
            // 실패 핸들러에서 또 실패하면 최종 방어
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


    private void clearCookie(HttpServletResponse res, String name, String domain) {
        Cookie cookie = new Cookie(name, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setDomain(domain);
        res.addCookie(cookie);
    }

    private String guessProviderFromRefererOrRequest(HttpServletRequest req) {
        String ref = req.getHeader("Referer");
        if (ref != null) {
            if (ref.contains("/oauth2/authorize/google")) return "google";
            if (ref.contains("/oauth2/authorize/kakao"))  return "kakao";
            if (ref.contains("/oauth2/authorize/naver"))  return "naver";
        }
        String uri = req.getRequestURI();
        if (uri != null) {
            if (uri.contains("/oauth2/authorize/google") || uri.contains("/oauth2/callback/google")) return "google";
            if (uri.contains("/oauth2/authorize/kakao")  || uri.contains("/oauth2/callback/kakao"))  return "kakao";
            if (uri.contains("/oauth2/authorize/naver")  || uri.contains("/oauth2/callback/naver"))  return "naver";
        }
        return "unknown";
    }

    private String safeMessage(String msg) {
        if (msg == null || msg.isBlank()) return "Authentication failed";
        // 너무 긴 내부 메시지/HTML 제거
        return msg.length() > 500 ? msg.substring(0, 500) + "..." : msg;
    }
}
