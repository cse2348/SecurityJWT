package com.example.securityjwt.Controller;

import com.example.securityjwt.Entity.User;
import com.example.securityjwt.Service.AuthService;
import com.example.securityjwt.Service.UserService;
import com.example.securityjwt.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth") // 이 컨트롤러의 모든 API 경로는 /auth로 시작
public class AuthController {

    private final AuthService authService; // 회원가입, 로그인 로직을 담당
    private final UserService userService; // 사용자 정보 조회를 담당

    // 회원가입 API : username, password를 요청 Body에서 받아서 회원가입 처리 -> 성공 시 회원가입 성공 메시지 반환
    @PostMapping("/signup")
    public ApiResponse<String> signup(@RequestBody Map<String, String> request) {
        authService.signup(request.get("username"), request.get("password"));
        return new ApiResponse<>(true, "회원가입 성공", null);
    }

    // 로그인 API : username, password를 요청 Body에서 받아서 로그인 처리 -> 성공 시 Access Token과 Refresh Token 반환
    @PostMapping("/login")
    public ApiResponse<Map<String, String>> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        // AccessToken, RefreshToken 발급 및 DB 저장은 AuthService에서 처리
        Map<String, String> tokens = authService.login(username, password);

        return new ApiResponse<>(true, "로그인 성공", tokens);
    }

    // 토큰 재발급 API : Refresh Token을 받아서 새로운 Access Token을 발급
    @PostMapping("/refresh")
    public ApiResponse<String> refresh(@RequestBody Map<String, String> request) {
        String token = authService.refresh(request.get("refreshToken"));
        return new ApiResponse<>(true, "토큰 재발급 성공", token);
    }

    // 로그인한 유저 정보 조회 API : JWT 인증 필터를 통과했기 때문에 SecurityContextHolder에 인증 정보(Authentication)가 있음
    // Authentication에서 username을 꺼내서 DB에서 User 정보를 조회해서 반환
    // Authorization: Bearer {AccessToken} 헤더 형태로 호출해야 함 -> 사용자 정보를 조회하거나, 인증이 필요한 API를 호출시 서버에게 인증했음을 증명
    @GetMapping("/me")
    public ApiResponse<User> getUserInfo(Authentication authentication) {
        String username = authentication.getName();
        User user = userService.findByUsername(username); // DB에서 사용자 정보 조회
        return new ApiResponse<>(true, "유저 정보 조회 성공", user);
    }
}
