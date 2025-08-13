package com.example.securityjwt.controller;

import com.example.securityjwt.common.ApiResponse;
import com.example.securityjwt.dto.LoginRequest;
import com.example.securityjwt.dto.SignupRequest;
import com.example.securityjwt.dto.TokenResponse;
import com.example.securityjwt.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;

// 인증 관련 API 컨트롤러: 회원가입 / 로그인 / 토큰 재발급
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    // 회원가입
    @PostMapping("/signup")
    public ApiResponse<String> signup(@Valid @RequestBody SignupRequest request) {
        boolean ok = authService.signup(request);
        return ok ? ApiResponse.success("회원가입 성공", null)
                : ApiResponse.failure("회원가입 실패");
    }

    // 로그인 → Access/Refresh 발급 (토큰은 JSON/쿠키 방식은 서비스 구현에 따름)
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        TokenResponse tokens = authService.login(request);
        return (tokens != null)
                ? ApiResponse.success("로그인 성공", tokens)
                : ApiResponse.failure("로그인 실패");
    }

    // 토큰 재발급: 1순위 쿠키(REFRESH_TOKEN) → 2순위 Authorization: Bearer
    @PostMapping("/refresh")
    public ApiResponse<TokenResponse> refresh(HttpServletRequest req,
                                              @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        String refresh = extractRefreshToken(req, authorization);
        TokenResponse tokens = authService.refresh(refresh);
        return (tokens != null)
                ? ApiResponse.success("토큰 재발급 성공", tokens)
                : ApiResponse.failure("토큰 재발급 실패");
    }

    // ===== 내부 유틸 =====
    private String extractRefreshToken(HttpServletRequest req, String authorization) {
        if (req.getCookies() != null) {
            for (Cookie c : req.getCookies()) {
                if ("REFRESH_TOKEN".equals(c.getName())) {
                    if (c.getValue() != null && !c.getValue().isBlank()) return c.getValue().trim();
                }
            }
        }
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring(7).trim();
        }
        return null;
    }
}
