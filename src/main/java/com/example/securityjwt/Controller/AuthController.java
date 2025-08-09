package com.example.securityjwt.Controller;

import com.example.securityjwt.dto.LoginRequest;
import com.example.securityjwt.dto.RefreshTokenRequest;
import com.example.securityjwt.dto.SignupRequest;
import com.example.securityjwt.dto.AuthResponse;
import com.example.securityjwt.dto.UserResponse;
import com.example.securityjwt.common.ApiResponse;
import com.example.securityjwt.Service.AuthService;
import com.example.securityjwt.Service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * 인증 관련 API를 처리하는 컨트롤러
 * - 회원가입, 로그인, 토큰 재발급, 현재 로그인된 사용자 정보 조회 기능 제공
 * - 모든 경로는 /auth로 시작
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth") // 이 컨트롤러의 모든 API 경로는 /auth로 시작
public class AuthController {

    private final AuthService authService; // 회원가입, 로그인 로직을 담당
    private final UserService userService; // 사용자 정보 조회를 담당

    /**
     * 회원가입 API
     * username, password를 요청 Body에서 받아서 회원가입 처리
     * - 요청 DTO: SignupRequest (username, password)
     * - @Valid로 유효성 검증
     * 성공 시: 회원가입 성공 메시지 반환
     * 실패 시: 회원가입 실패 메시지 반환
     */
    @PostMapping("/signup")
    public ApiResponse<String> signup(@Valid @RequestBody SignupRequest request) {
        boolean result = authService.signup(request);
        return result
                ? ApiResponse.success("회원가입 성공", null)
                : ApiResponse.failure("회원가입 실패");
    }

    /**
     * 로그인 API
     * username, password를 요청 Body에서 받아서 로그인 처리
     * - 요청 DTO: LoginRequest
     * - @Valid로 유효성 검증
     * 성공 시: Access Token과 Refresh Token 반환
     * 실패 시: 로그인 실패 메시지 반환
     * AccessToken, RefreshToken 발급 및 DB 저장은 AuthService에서 처리
     */
    @PostMapping("/login")
    public ApiResponse<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return (response != null)
                ? ApiResponse.success("로그인 성공", response)
                : ApiResponse.failure("로그인 실패");
    }

    /**
     * 토큰 재발급 API
     * Refresh Token을 요청 Body에서 받아서 새로운 Access Token을 발급
     * - 요청 DTO: RefreshTokenRequest
     * 성공 시: 새 Access Token과 기존 또는 새 Refresh Token 반환
     * 실패 시: 토큰 재발급 실패 메시지 반환
     */
    @PostMapping("/refresh")
    public ApiResponse<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refresh(request.getRefreshToken());
        return (response != null)
                ? ApiResponse.success("토큰 재발급 성공", response)
                : ApiResponse.failure("토큰 재발급 실패");
    }

    /**
     * 로그인한 유저 정보 조회 API
     * JWT 인증 필터를 통과했기 때문에 SecurityContextHolder에 인증 정보(Authentication)가 존재
     * Authentication에서 username을 꺼내서 DB에서 User 정보를 조회하여 반환
     * - Authorization: Bearer {AccessToken} 헤더 형태로 호출해야 함
     * - 이 API를 호출하면 현재 인증된 사용자의 정보를 조회하거나 인증이 필요한 API 호출 시 서버에 인증을 증명
     */
    @GetMapping("/me")
    public ApiResponse<UserResponse> getUserInfo(Authentication authentication) {
        UserResponse user = userService.getCurrentUser(authentication);
        return (user != null)
                ? ApiResponse.success("유저 정보 조회 성공", user)
                : ApiResponse.failure("유저 정보 조회 실패");
    }
}
