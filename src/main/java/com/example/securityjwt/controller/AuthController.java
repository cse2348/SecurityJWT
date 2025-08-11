package com.example.securityjwt.controller;

import com.example.securityjwt.common.ApiResponse;
import com.example.securityjwt.dto.LoginRequest;
import com.example.securityjwt.dto.SignupRequest;
import com.example.securityjwt.dto.TokenResponse;
import com.example.securityjwt.dto.UserResponse;
import com.example.securityjwt.service.AuthService;
import com.example.securityjwt.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

//인증 관련 API를 처리하는 컨트롤러 -> 회원가입, 로그인, 토큰 재발급, 현재 로그인된 사용자 정보 조회 기능 제공
// 모든 경로는 /auth로 시작
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth") // 이 컨트롤러의 모든 API 경로는 /auth로 시작
public class AuthController {

    private final AuthService authService; // 회원가입, 로그인 로직을 담당
    private final UserService userService; // 사용자 정보 조회를 담당

    // 회원가입 API -> 요청 DTO: SignupRequest (username, password, name?, email?)
    @PostMapping("/signup")
    public ApiResponse<String> signup(@Valid @RequestBody SignupRequest request) {
        boolean result = authService.signup(request);
        return result
                ? ApiResponse.success("회원가입 성공", null)
                : ApiResponse.failure("회원가입 실패");
    }

    // 로그인 API -> 요청 DTO: LoginRequest ; 성공 시: TokenResponse(access, refresh) 반환
    @PostMapping("/login")
    public ApiResponse<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        TokenResponse tokens = authService.login(request);
        return (tokens != null)
                ? ApiResponse.success("로그인 성공", tokens)
                : ApiResponse.failure("로그인 실패");
    }

    //  토큰 재발급 API -> 바디 DTO 없이 진행(요구: DTO 4개만 사용 , 우선순위: 쿠키(REFRESH_TOKEN) → Authorization: Bearer {token}
    @PostMapping("/refresh")
    public ApiResponse<TokenResponse> refresh(HttpServletRequest req,
                                              @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        String refresh = extractRefreshToken(req, authorization);
        TokenResponse tokens = authService.refresh(refresh);
        return (tokens != null)
                ? ApiResponse.success("토큰 재발급 성공", tokens)
                : ApiResponse.failure("토큰 재발급 실패");
    }

    // 로그인한 유저 정보 조회 API -> Authentication에서 현재 사용자 식별값을 꺼내 UserService가 UserResponse로 변환
    @GetMapping("/me")
    public ApiResponse<UserResponse> getUserInfo(Authentication authentication) {
        UserResponse user = userService.getCurrentUser(authentication);
        return (user != null)
                ? ApiResponse.success("유저 정보 조회 성공", user)
                : ApiResponse.failure("유저 정보 조회 실패");
    }

    //  Refresh 토큰 추출 -> 1순위: 쿠키의 REFRESH_TOKEN, 2순위: Authorization 헤더의 Bearer 값
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
