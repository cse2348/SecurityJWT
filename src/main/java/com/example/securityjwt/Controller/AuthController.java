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
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    @PostMapping("/signup")
    public ApiResponse<String> signup(@RequestBody Map<String, String> request) {
        authService.signup(request.get("username"), request.get("password"));
        return new ApiResponse<>(true, "회원가입 성공", null);
    }

    @PostMapping("/login")
    public ApiResponse<String> login(@RequestBody Map<String, String> request) {
        String token = authService.login(request.get("username"), request.get("password"));
        return new ApiResponse<>(true, "로그인 성공", token);
    }

    @PostMapping("/refresh")
    public ApiResponse<String> refresh(@RequestBody Map<String, String> request) {
        String token = authService.refresh(request.get("refreshToken"));
        return new ApiResponse<>(true, "토큰 재발급 성공", token);
    }

    @GetMapping("/me")
    public ApiResponse<User> getUserInfo(Authentication authentication) {
        String username = authentication.getName();
        User user = userService.findByUsername(username);
        return new ApiResponse<>(true, "유저 정보 조회 성공", user);
    }
}
