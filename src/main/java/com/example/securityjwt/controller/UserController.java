package com.example.securityjwt.controller;

import com.example.securityjwt.common.ApiResponse;
import com.example.securityjwt.dto.UserResponse;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// 보호 API 컨트롤러 ; /user/me : 현재 인증된 사용자 정보 반환 -> JwtAuthenticationFilter가 SecurityContext에 인증을 세팅해줘야 동작함
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    // 현재 로그인한 사용자 정보 조회 -> principal 타입이 우리 엔티티(User)일 수도, Spring의 UserDetails일 수도 있으므로 모두 처리
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> me(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            // 401 Unauthorized
            return ResponseEntity.status(401).body(ApiResponse.failure("Unauthorized"));
        }

        Object principal = authentication.getPrincipal();

        // 우리 애플리케이션의 User 엔티티가 바로 Principal인 경우
        if (principal instanceof User appUser) {
            return ResponseEntity.ok(ApiResponse.success(UserResponse.from(appUser)));
        }

        // Spring Security의 UserDetails인 경우 (username으로 User를 다시 조회)
        if (principal instanceof UserDetails springUser) {
            return userRepository.findByUsername(springUser.getUsername())
                    .map(UserResponse::from)
                    .map(ApiResponse::success)
                    .map(ResponseEntity::ok)
                    // 404 Not Found
                    .orElseGet(() -> ResponseEntity.status(404).body(ApiResponse.failure("User not found")));
        }

        // 그 외 예상치 못한 형태 -> 500
        return ResponseEntity.status(500).body(ApiResponse.failure("Unsupported principal type"));
    }
}
