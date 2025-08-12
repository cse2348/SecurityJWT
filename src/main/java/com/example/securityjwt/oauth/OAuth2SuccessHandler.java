package com.example.securityjwt.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();
    // JWT가 필요하면 주입해서 생성 후 body에 실어주면 됨
    // private final JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            OAuth2User principal = (OAuth2User) authentication.getPrincipal();

            // 예시: 식별/프로필 정보 뽑기
            String email = (String) principal.getAttributes().getOrDefault("email", "");
            if (email.isBlank()) {
                Object kakaoAccount = principal.getAttribute("kakao_account");
                if (kakaoAccount instanceof Map<?,?> map && map.get("email") instanceof String e) email = e;
                Object naverResp = principal.getAttribute("response");
                if (naverResp instanceof Map<?,?> map && map.get("email") instanceof String e) email = e;
            }

            // 필요 시 JWT 생성
            // String token = jwtUtil.createToken(email, "ROLE_USER");

            Map<String, Object> body = new HashMap<>();
            body.put("status", "success");
            body.put("providerAttributes", principal.getAttributes());
            body.put("email", email);
            // body.put("token", token);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType("application/json");
            objectMapper.writeValue(response.getWriter(), body);
        } catch (Exception e) {
            // 실패 형식과 통일을 원하면 401/400 등으로 내려도 됨
            try {
                response.setStatus(HttpServletResponse.SC_OK);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.setContentType("application/json");
                objectMapper.writeValue(response.getWriter(), Map.of(
                        "status", "error",
                        "message", "OAuth2 success handling failed"
                ));
            } catch (Exception ignored) {}
        }
    }
}
